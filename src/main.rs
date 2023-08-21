mod args;
mod helper;
mod progress_manager;
mod sfv_manager;

use anyhow::bail;
use args::{Args, Format};
use clap::Parser;
use crossbeam_channel::{Receiver, Sender};
use helper::*;
use progress_manager::*;
use walkdir::WalkDir;

use std::{
    cell::UnsafeCell,
    collections::{HashMap, HashSet},
    env,
    fs::OpenOptions,
    io::{IsTerminal, Read},
    path::{Path, PathBuf},
    sync::Arc,
    thread, vec,
};

use bytesize::ByteSize;
use libmhash::prelude::*;
use libmhash::{hasher_server::Identifier, paranoid_hash::HasherTag};

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let block_size: usize = args
        .block_size
        .parse::<ByteSize>()
        .expect("Invalid size.")
        .as_u64()
        .try_into()
        .expect("Block size is too large.");

    if args.check.as_ref().is_some_and(|c| c.is_some()) && args.update.is_some() {
        bail!("Can't specify update path and check path at the same time");
    }

    if args.check.as_ref().is_some_and(|c| c.is_none()) && args.update.is_none() {
        bail!("Must specify either check path or update path");
    }

    let (progress_sender, progress_receiver) = crossbeam_channel::unbounded::<ProgressWrapper>();

    let b = Builder::new()
        .block_count(args.block_count)
        .block_size(block_size)
        .on_result(Some(|r: &HasherResult<'_, _>| {
            progress_sender
                .send(ProgressWrapper::Result {
                    identifier: r.identifier.clone(),
                    tag: r.tag,
                    digest: hex::encode(r.hasher.digest().unwrap()),
                })
                .unwrap();
        }))
        .on_error(Some(|e: &HasherError<_>| {
            progress_sender
                .send(ProgressWrapper::HashingError {
                    identifier: e.identifier.clone(),
                    tag: e.tag,
                    message: e.error.to_string(),
                })
                .unwrap();
        }));

    let b = if !args.no_progress {
        b.on_progress(Some(|p: &HasherProgress<_>| {
            if p.total_data_length == p.processed_data_length {
                return;
            }

            progress_sender
                .send(ProgressWrapper::Progress {
                    identifier: p.identifier.clone(),
                    tag: p.tag,
                    total_data_length: p.total_data_length,
                    position: p.processed_data_length,
                })
                .unwrap();
        }))
    } else {
        b.on_progress(None)
    };

    let (mut file, root) = if let Some(path) = args.update.as_ref() {
        (
            Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .read(true)
                    .write(true)
                    .open(path)?,
            ),
            path.parent().unwrap().to_owned(),
        )
    } else if let Some(path) = args.output.as_ref() {
        (
            Some(
                OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .open(path)?,
            ),
            path.parent().unwrap().to_owned(),
        )
    } else if let Some(Some(path)) = args.check.as_ref() {
        (
            Some(OpenOptions::new().read(true).open(path)?),
            path.parent().unwrap().to_owned(),
        )
    } else {
        (None, env::current_dir()?)
    };

    let old_data = match args.check.is_some() || args.update.is_some() {
        true => {
            let mut buf = String::new();
            file.as_mut().unwrap().read_to_string(&mut buf)?;
            buf
        }
        false => String::new(),
    };

    if args.update.is_some() {
        file.as_mut().unwrap().set_len(0)?;
    }

    let sfv_builder = sfv_manager::SfvManagerBuilder::new()
        .format(args.format)
        .has_header(args.header)
        .root_path(root.clone())
        .old_data(old_data);

    let sfv = match args.update.is_some() || args.output.is_some() {
        true => sfv_builder.writer(file.unwrap()).build(),
        false => match args.no_progress || !std::io::stdout().is_terminal() {
            true => sfv_builder.writer(std::io::stdout()).build(),
            false => sfv_builder.writer(std::io::sink()).build(),
        },
    };

    let sfv = SyncUnsafeCell::new(sfv);

    if args.check.is_some() {
        check(
            &args,
            block_size,
            b,
            progress_sender.clone(),
            progress_receiver.clone(),
            &sfv,
        )?;
    }

    if args.output.is_some() || args.update.is_some() || !args.paths.is_empty() {
        update(
            args,
            b,
            progress_sender.clone(),
            progress_receiver,
            sfv.get_mut(),
            &root,
        )?;
    }

    Ok(())
}

fn check(
    args: &Args,
    block_size: usize,
    b: impl BuilderTrait<Tag = HasherTag>,
    progress_sender: Sender<ProgressWrapper>,
    progress_receiver: Receiver<ProgressWrapper>,
    sfv: &SyncUnsafeCell<sfv_manager::SfvManager>,
) -> anyhow::Result<()> {
    let b = b.identifier_count(args.file_count.unwrap_or_else(num_cpus::get));

    thread::scope(|s| {
        let mut server = b.build().unwrap();
        let data_sender = server.data_sender();

        let creation_sender = progress_sender.clone();

        let sfv_for_iter = sfv.get_mut();
        let sfv_for_update = sfv.get_mut();

        s.spawn(move || {
            for file_info in sfv_for_iter.files() {
                let file_info = match file_info {
                    sfv_manager::ItemType::File(file) => file,
                    sfv_manager::ItemType::Error(e) => {
                        creation_sender
                            .send(ProgressWrapper::FileError {
                                identifier: e.as_str().into(),
                                message: "Text can't be parsed".to_owned(),
                            })
                            .unwrap();
                        continue;
                    }
                };

                if file_info.digests.is_none() {
                    continue;
                }

                let file_size = match file_info.path.metadata() {
                    Ok(meta) => meta.len(),
                    Err(e) => {
                        creation_sender
                            .send(ProgressWrapper::FileError {
                                identifier: file_info.path.clone().into(),
                                message: e.to_string(),
                            })
                            .unwrap();
                        continue;
                    }
                };

                let mut possible_tags = HashSet::new();
                let mut tag_to_digests = HashMap::new();
                let mut digest_infos = vec![];

                if let Some(digests) = file_info.digests.as_ref() {
                    for (digest, tag) in digests {
                        let mut possible_tags_for_this = vec![];

                        match tag {
                            Some(tag) => {
                                possible_tags_for_this.push(*tag);
                            }
                            None => {
                                let tags = get_possible_tags(digest);
                                if let Some(tags) = tags {
                                    possible_tags_for_this.extend(tags);
                                }
                            }
                        }

                        possible_tags.extend(&possible_tags_for_this);

                        for tag in &possible_tags_for_this {
                            let ds = tag_to_digests.entry(*tag).or_insert_with(Vec::new);
                            ds.push(digest.clone());
                        }

                        digest_infos.push(DigestInfos {
                            digest: digest.to_owned(),
                            exact_tag: *tag,
                            possible_tags_count: possible_tags_for_this.len(),
                            matched: false,
                        });
                    }
                }

                creation_sender
                    .send(ProgressWrapper::Create {
                        id: file_info.path.clone().into(),
                        short_id: file_info.relative_path.clone().into(),
                        file_size,
                        tag_count: possible_tags.len(),
                        digest_infos: Some(digest_infos),
                        tag_to_digests: Some(tag_to_digests),
                    })
                    .unwrap();

                if !possible_tags.is_empty() {
                    let hashers: Vec<HasherWrapper<_>> = possible_tags
                        .iter()
                        .map(|t| HasherWrapper::create_from_tag(*t))
                        .collect();
                    data_sender.push_file(file_info.path.clone(), hashers);
                }
            }

            data_sender.end();
        });

        s.spawn(move || {
            struct ProgressDetails {
                index: usize,
                digests: Vec<DigestInfos>,
                info: ProgressFileInfo,
                tag_to_digests: HashMap<HasherTag, Vec<String>>,
            }

            fn print_and_clean(
                index_waiting_for_output: &mut usize,
                id_to_progress_details: &mut HashMap<Identifier, ProgressDetails>,
            ) {
                let mut details_list = id_to_progress_details
                    .iter()
                    .filter(|(_, detail)| detail.info.finished_tags == detail.info.total_tags)
                    .collect::<Vec<_>>();

                details_list.sort_unstable_by(|a, b| a.1.index.cmp(&b.1.index));

                let mut ids_to_be_removed = vec![];

                for (id, detail) in details_list {
                    if detail.index != *index_waiting_for_output {
                        break;
                    }

                    *index_waiting_for_output += 1;
                    ids_to_be_removed.push(id.clone());

                    let mut all_ok = true;
                    for di in &detail.digests {
                        all_ok &= di.matched;
                        if !di.matched {
                            println!("[{}][{}][No Matches]", detail.info.short_id, di.digest);
                        }
                    }

                    if all_ok {
                        println!("[{}][OK]", detail.info.short_id);
                    }
                }

                for id in ids_to_be_removed {
                    id_to_progress_details.remove(&id);
                }
            }

            let print_to_stdout = args.no_progress || !std::io::stdout().is_terminal();

            let mut pm = ProgressManager::new(Some(16));

            let mut id_to_progress_details = HashMap::new();

            let mut current_index: usize = 0;
            let mut index_waiting_for_output: usize = 0;

            let mut sum_file = 0u64;
            let mut sum_error = 0u64;
            let mut sum_matched_file = 0u64;
            let mut sum_unknown_digest = 0u64;

            loop {
                match progress_receiver.recv().unwrap() {
                    ProgressWrapper::Create {
                        id,
                        short_id,
                        file_size,
                        tag_count,
                        digest_infos,
                        tag_to_digests,
                    } => {
                        let digest_infos = digest_infos.unwrap();

                        sum_file += 1;

                        if print_to_stdout {
                            for digest_info in &digest_infos {
                                if digest_info.possible_tags_count == 0 {
                                    println!(
                                        "[{}][{}][Unknown Digest]",
                                        short_id, digest_info.digest
                                    );

                                    sum_unknown_digest += 1;
                                }
                            }
                        }

                        if !args.no_progress {
                            let pg = pm.get_or_insert(
                                short_id.clone(),
                                1,
                                digest_infos.iter().map(|d| &d.digest),
                            );
                            for digest_info in &digest_infos {
                                if digest_info.possible_tags_count == 0 {
                                    pg.complete_hash(&digest_info.digest, "Unknown Digest");

                                    sum_unknown_digest += 1;
                                } else {
                                    pg.set_length(
                                        &digest_info.digest,
                                        file_size * digest_info.possible_tags_count as u64,
                                    )
                                }
                            }

                            pm.refresh().unwrap();
                        }

                        if tag_count != 0 {
                            let progress_details = ProgressFileInfo {
                                short_id: short_id.clone(),
                                total_tags: tag_count,
                                finished_tags: 0,
                                last_piece_size: (file_size % block_size as u64) as usize,
                            };

                            id_to_progress_details.insert(
                                id.clone(),
                                ProgressDetails {
                                    info: progress_details,
                                    index: current_index,
                                    digests: digest_infos,
                                    tag_to_digests: tag_to_digests.unwrap(),
                                },
                            );

                            current_index += 1;
                        }
                    }
                    ProgressWrapper::FileError {
                        identifier,
                        message,
                    } => {
                        sum_file += 1;
                        sum_error += 1;

                        if print_to_stdout {
                            println!("[{}][ERROR][{}]", identifier, message);
                        }

                        if !args.no_progress {
                            pm.insert_error(&identifier, &message);
                            pm.refresh().unwrap();
                        }
                    }
                    ProgressWrapper::Result {
                        identifier,
                        tag,
                        digest,
                    } => {
                        let progress_details = id_to_progress_details.get_mut(&identifier).unwrap();
                        progress_details.info.finished_tags += 1;

                        for ds in &mut progress_details.digests {
                            if ds.digest == digest && ds.exact_tag.map_or(true, |t| t == tag) {
                                ds.matched = true;

                                if ds.exact_tag.is_none() {
                                    let path = match identifier.clone() {
                                        Identifier::Path(p) => p,
                                        Identifier::Name(_) => unreachable!(),
                                    };

                                    sfv_for_update.update(
                                        path,
                                        None,
                                        None,
                                        Some([(digest.clone(), Some(tag))].into_iter()),
                                    );
                                }

                                break;
                            }
                        }

                        if !args.no_progress {
                            let item = pm.get(&progress_details.info.short_id);
                            for digest_item in &progress_details.tag_to_digests[&tag] {
                                item.inc(digest_item, progress_details.info.last_piece_size as u64);

                                if *digest_item == digest {
                                    item.complete_hash(
                                        &digest,
                                        &format!("{} matched", tag_to_str(&tag)),
                                    );
                                }
                            }

                            if progress_details.info.finished_tags
                                == progress_details.info.total_tags
                            {
                                item.complete_all_hash("No match");
                            }

                            pm.refresh().unwrap();
                        }

                        if progress_details.info.finished_tags == progress_details.info.total_tags {
                            if progress_details.digests.iter().all(|d| d.matched) {
                                sum_matched_file += 1;
                            }

                            if print_to_stdout {
                                print_and_clean(
                                    &mut index_waiting_for_output,
                                    &mut id_to_progress_details,
                                );
                            } else {
                                id_to_progress_details.remove(&identifier);
                            }
                        }
                    }
                    ProgressWrapper::HashingError {
                        identifier,
                        tag,
                        message,
                    } => match tag {
                        Some(tag) => {
                            let progress_details =
                                id_to_progress_details.get_mut(&identifier).unwrap();
                            progress_details.info.finished_tags += 1;

                            if print_to_stdout {
                                println!(
                                    "[{}][{}][{}]",
                                    progress_details.info.short_id,
                                    tag_to_str(&tag),
                                    message
                                );
                            }

                            if !args.no_progress {
                                let item = pm.get(&progress_details.info.short_id);
                                for digest in &progress_details.tag_to_digests[&tag] {
                                    item.complete_hash(digest, &message);
                                }

                                if progress_details.info.finished_tags
                                    == progress_details.info.total_tags
                                {
                                    item.complete_all_hash("No match");
                                }

                                pm.refresh().unwrap();
                            }

                            if progress_details.info.finished_tags
                                == progress_details.info.total_tags
                            {
                                if print_to_stdout {
                                    print_and_clean(
                                        &mut index_waiting_for_output,
                                        &mut id_to_progress_details,
                                    );
                                } else {
                                    id_to_progress_details.remove(&identifier);
                                }
                            }
                        }
                        None => {
                            let progress_details =
                                id_to_progress_details.get_mut(&identifier).unwrap();
                            progress_details.info.finished_tags = progress_details.info.total_tags;

                            if print_to_stdout {
                                println!(
                                    "[{}][ERROR][{}]",
                                    progress_details.info.short_id, message
                                );

                                print_and_clean(
                                    &mut index_waiting_for_output,
                                    &mut id_to_progress_details,
                                );
                            } else {
                                id_to_progress_details.remove(&identifier);
                            }

                            if !args.no_progress {
                                pm.complete_file(&identifier, &message);
                                pm.refresh().unwrap();
                            }
                        }
                    },
                    ProgressWrapper::Progress {
                        identifier,
                        tag,
                        total_data_length: _,
                        position: _,
                    } => {
                        if args.no_progress {
                            continue;
                        }

                        let progress_details = id_to_progress_details.get(&identifier).unwrap();
                        let item = pm.get(&progress_details.info.short_id);
                        for digest in &progress_details.tag_to_digests[&tag] {
                            item.inc(digest, block_size as u64);
                        }
                    }
                    ProgressWrapper::End => break,
                }
            }

            println!("\nSummary:");
            println!("    File count: {}", sum_file);
            println!("    Matched file count: {}", sum_matched_file);
            println!("    Error file count: {}", sum_error);
            println!("    Unknow digest count: {}", sum_unknown_digest)
        });

        server.compute();
        progress_sender.send(ProgressWrapper::End).unwrap();
    });

    Ok(())
}

fn trim_path<'a>(path: &'a Path, root: &'a Path) -> &'a Path {
    let path = path.strip_prefix("./").unwrap_or(path);
    path.strip_prefix(root).unwrap_or(path)
}

fn update(
    args: Args,
    b: impl BuilderTrait<Tag = HasherTag>,
    progress_sender: Sender<ProgressWrapper>,
    progress_receiver: Receiver<ProgressWrapper>,
    sfv: &mut sfv_manager::SfvManager,
    root: &Path,
) -> anyhow::Result<()> {
    let tags = get_hasher_tags(&args);

    let b = if tags.is_empty() {
        if args.paths.is_empty() && args.update.is_some() {
            b.identifier_count(1)
        } else {
            bail!("No hash specified");
        }
    } else {
        b.identifier_count(
            args.file_count
                .unwrap_or_else(|| num_cpus::get() / tags.len()),
        )
    };

    let str_tags = tags
        .iter()
        .map(|t| tag_to_str(t).to_owned())
        .collect::<Vec<_>>();

    let format = match sfv.format() {
        Format::Auto => match tags.len() {
            1 => Format::CoreUtils,
            _ => Format::Sfv,
        },
        others => others,
    };
    sfv.set_format(format);

    let output_path = match args.output.as_ref().or(args.update.as_ref()) {
        Some(path) => path.canonicalize()?,
        None => PathBuf::from("/"),
    };

    thread::scope(|s| {
        let progress_sender = &progress_sender;
        let mut server = b.build().unwrap();
        let data_sender = server.data_sender();
        let tags: Arc<[HasherTag]> = Arc::from(tags);

        let parse_errors = sfv
            .files()
            .iter()
            .filter_map(|i| match i {
                sfv_manager::ItemType::File(_) => None,
                sfv_manager::ItemType::Error(e) => Some(e.to_owned()),
            })
            .collect::<Vec<_>>();

        s.spawn(move || {
            for item in parse_errors {
                progress_sender
                    .send(ProgressWrapper::FileError {
                        identifier: item.into(),
                        message: "Text can't be parsed".to_owned(),
                    })
                    .unwrap();
            }

            for path in &args.paths {
                let is_dir = match path.metadata() {
                    Ok(meta) => meta.is_dir(),
                    Err(error) => {
                        progress_sender
                            .send(ProgressWrapper::FileError {
                                identifier: trim_path(path, root).into(),
                                message: error.to_string(),
                            })
                            .unwrap();

                        continue;
                    }
                };

                if is_dir && !args.recursive {
                    progress_sender
                        .send(ProgressWrapper::FileError {
                            identifier: trim_path(path, root).into(),
                            message: "Not a file.".to_owned(),
                        })
                        .unwrap();

                    continue;
                }

                if !is_dir {
                    let path = path.strip_prefix(",/").unwrap_or(path);
                    let short_path = path.strip_prefix(root).unwrap_or(path);
                    progress_sender
                        .send(ProgressWrapper::Create {
                            id: path.into(),
                            short_id: short_path.into(),
                            file_size: 0,
                            tag_count: tags.len(),
                            digest_infos: None,
                            tag_to_digests: None,
                        })
                        .unwrap();
                    data_sender.push_file(
                        path,
                        tags.iter()
                            .map(|t| HasherWrapper::create_from_tag(*t))
                            .collect(),
                    );

                    continue;
                }

                for entry in WalkDir::new(path).follow_links(args.follow) {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(error) => {
                            let id: Identifier = error
                                .path()
                                .map(|p| trim_path(p, root).into())
                                .unwrap_or_else(|| "Invalid path".into());

                            progress_sender
                                .send(ProgressWrapper::FileError {
                                    identifier: id,
                                    message: error.to_string(),
                                })
                                .unwrap();

                            continue;
                        }
                    };

                    if entry.file_type().is_file() {
                        let path = entry.path();
                        if path.canonicalize().is_ok_and(|p| p == output_path) {
                            continue;
                        }

                        let path = path.strip_prefix(",/").unwrap_or(path);
                        let short_path = path.strip_prefix(root).unwrap_or(path);
                        progress_sender
                            .send(ProgressWrapper::Create {
                                id: path.into(),
                                short_id: short_path.into(),
                                file_size: 0,
                                tag_count: tags.len(),
                                digest_infos: None,
                                tag_to_digests: None,
                            })
                            .unwrap();
                        data_sender.push_file(
                            path,
                            tags.iter()
                                .map(|t| HasherWrapper::create_from_tag(*t))
                                .collect(),
                        );
                    }
                }
            }

            data_sender.end();
        });

        s.spawn(move || {
            let immediate = args.sort.is_empty() && !args.header;
            let should_output = args.no_progress
                || !std::io::stdout().is_terminal()
                || args.output.is_some()
                || args.update.is_some();

            let mut pm = ProgressManager::new(None);
            let mut id_to_progress_details = HashMap::new();

            if should_output && immediate {
                sfv.try_output();
                sfv.clear();
            }

            loop {
                match progress_receiver.recv().unwrap() {
                    ProgressWrapper::Create {
                        id,
                        short_id,
                        file_size: _,
                        tag_count,
                        digest_infos: _,
                        tag_to_digests: _,
                    } => {
                        id_to_progress_details.insert(
                            id,
                            ProgressFileInfo {
                                short_id,
                                total_tags: tag_count,
                                finished_tags: 0,
                                last_piece_size: 0,
                            },
                        );
                    }
                    ProgressWrapper::FileError {
                        identifier,
                        message,
                    } => {
                        if args.no_progress {
                            eprintln!("[{}][ERROR][{}]", identifier, message);
                        } else {
                            pm.insert_error(&identifier, &message);
                            pm.refresh().unwrap();
                        }
                    }
                    ProgressWrapper::Result {
                        identifier,
                        tag,
                        digest,
                    } => {
                        let progress_details = id_to_progress_details.get_mut(&identifier).unwrap();
                        progress_details.finished_tags += 1;

                        if !args.no_progress {
                            let item = pm.get_or_insert(
                                progress_details.short_id.clone(),
                                u64::MAX,
                                str_tags.iter(),
                            );
                            item.complete_hash(tag_to_str(&tag), &digest);

                            pm.refresh().unwrap();
                        }

                        let path = match identifier.clone() {
                            Identifier::Path(path) => path,
                            Identifier::Name(_) => unreachable!(),
                        };

                        if should_output {
                            sfv.update(
                                path.clone(),
                                None,
                                None,
                                Some([(digest, Some(tag))].into_iter()),
                            );
                        }

                        if progress_details.finished_tags == progress_details.total_tags {
                            if immediate {
                                sfv.try_output_file(&path);
                                sfv.try_swap_remove(&path);
                            }

                            id_to_progress_details.remove(&identifier);
                        }
                    }
                    ProgressWrapper::HashingError {
                        identifier,
                        tag,
                        message,
                    } => match tag {
                        Some(tag) => {
                            let progress_details =
                                id_to_progress_details.get_mut(&identifier).unwrap();
                            progress_details.finished_tags += 1;

                            if args.no_progress {
                                eprintln!(
                                    "[{}][{}][{}]",
                                    progress_details.short_id,
                                    tag_to_str(&tag),
                                    message
                                );
                            } else {
                                let item = pm.get_or_insert(
                                    progress_details.short_id.clone(),
                                    u64::MAX,
                                    str_tags.iter(),
                                );
                                item.complete_hash(tag_to_str(&tag), &message);

                                pm.refresh().unwrap();
                            }

                            if progress_details.finished_tags == progress_details.total_tags {
                                id_to_progress_details.remove(&identifier);

                                let path = match identifier {
                                    Identifier::Path(path) => path,
                                    Identifier::Name(_) => unreachable!(),
                                };

                                if immediate {
                                    sfv.try_output_file(&path);
                                    sfv.try_swap_remove(&path);
                                }
                            }
                        }
                        None => {
                            let progress_details =
                                id_to_progress_details.remove(&identifier).unwrap();
                            if args.no_progress {
                                eprintln!("[{}][ERROR][{}]", progress_details.short_id, message);
                            } else {
                                pm.complete_file(&progress_details.short_id, &message);
                                pm.refresh().unwrap();
                            }

                            if immediate {
                                let path = match identifier {
                                    Identifier::Path(path) => path,
                                    Identifier::Name(_) => unreachable!(),
                                };

                                sfv.try_output_file(&path);
                                sfv.try_swap_remove(&path);
                            }
                        }
                    },
                    ProgressWrapper::Progress {
                        identifier,
                        tag,
                        total_data_length,
                        position,
                    } => {
                        if args.no_progress {
                            continue;
                        }

                        let progress_details = id_to_progress_details.get(&identifier).unwrap();
                        let item = pm.get_or_insert(
                            progress_details.short_id.clone(),
                            total_data_length,
                            str_tags.iter(),
                        );
                        item.set_position(tag_to_str(&tag), position);

                        pm.refresh().unwrap();
                    }
                    ProgressWrapper::End => break,
                }
            }

            if should_output {
                sfv.sort(&args.sort);
                sfv.try_output();
            }
        });

        server.compute();
        progress_sender.send(ProgressWrapper::End).unwrap();
    });

    Ok(())
}

enum ProgressWrapper {
    Create {
        id: Identifier,
        short_id: Identifier,
        file_size: u64,
        tag_count: usize,
        digest_infos: Option<Vec<DigestInfos>>,
        tag_to_digests: Option<HashMap<HasherTag, Vec<String>>>,
    },
    FileError {
        identifier: Identifier,
        message: String,
    },
    Result {
        identifier: Identifier,
        tag: HasherTag,
        digest: String,
    },
    HashingError {
        identifier: Identifier,
        tag: Option<HasherTag>,
        message: String,
    },
    Progress {
        identifier: Identifier,
        tag: HasherTag,
        total_data_length: u64,
        position: u64,
    },
    End,
}

struct ProgressFileInfo {
    short_id: Identifier,
    total_tags: usize,
    finished_tags: usize,
    last_piece_size: usize,
}

struct DigestInfos {
    digest: String,
    exact_tag: Option<HasherTag>,
    possible_tags_count: usize,
    matched: bool,
}

#[repr(transparent)]
pub struct SyncUnsafeCell<T: ?Sized>(UnsafeCell<T>);

unsafe impl<T: ?Sized> Send for SyncUnsafeCell<T> {}

unsafe impl<T: ?Sized> Sync for SyncUnsafeCell<T> {}

impl<T> SyncUnsafeCell<T> {
    pub const fn new(value: T) -> SyncUnsafeCell<T> {
        SyncUnsafeCell(UnsafeCell::new(value))
    }
}

impl<T: ?Sized> SyncUnsafeCell<T> {
    #[allow(clippy::mut_from_ref)]
    pub fn get_mut(&self) -> &mut T {
        unsafe { &mut *self.0.get() }
    }
}
