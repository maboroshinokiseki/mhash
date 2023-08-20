use std::{
    cell::UnsafeCell,
    cmp::Ordering,
    collections::HashMap,
    env,
    fs::Metadata,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};

use chrono::prelude::*;
use libmhash::paranoid_hash::HasherTag;
use regex::Regex;

use crate::helper::{get_possible_tags, tag_to_str};

pub struct SfvManagerBuilder {
    has_header: bool,
    format: crate::Format,
    old_data: Option<String>,
    root: Option<PathBuf>,
    writer: Option<Box<dyn Write + Send>>,
}

impl SfvManagerBuilder {
    pub fn new() -> Self {
        Self {
            has_header: false,
            format: crate::Format::Auto,
            old_data: None,
            root: None,
            writer: None,
        }
    }

    pub fn has_header(self, has_header: bool) -> Self {
        Self { has_header, ..self }
    }

    pub fn format(self, format: crate::Format) -> Self {
        Self { format, ..self }
    }

    pub fn root_path(self, root: PathBuf) -> Self {
        Self {
            root: Some(root),
            ..self
        }
    }

    pub fn old_data(self, old_data: String) -> Self {
        Self {
            old_data: Some(old_data),
            ..self
        }
    }

    pub fn writer(self, writer: impl Write + Send + 'static) -> Self {
        Self {
            writer: Some(Box::new(writer)),
            ..self
        }
    }

    fn update(
        manager: &mut SfvManager,
        possible_file: &mut Option<FileInfo>,
        file: Option<FileInfo>,
        comment: &mut String,
        dont_check_file_exists: bool,
    ) -> bool {
        if let Some(file) = file {
            if dont_check_file_exists || file.path.exists() {
                manager.update(
                    Arc::clone(&file.path),
                    file.size,
                    file.modify_time,
                    file.digests.map(|d| {
                        d.into_iter().map(|(d, t)| match t {
                            Some(t) => (d, Some(t)),
                            None => {
                                let tags = get_possible_tags(&d);
                                match tags {
                                    Some(tags) => match tags.len() {
                                        1 => (d, Some(tags[0])),
                                        _ => (d, None),
                                    },
                                    None => (d, None),
                                }
                            }
                        })
                    }),
                );
                if !comment.is_empty() {
                    manager.append_file_comment_line(&file.path, comment);
                    comment.clear();
                }
                return true;
            } else {
                possible_file.get_or_insert(file);
            }
        }

        false
    }

    pub fn build(self) -> SfvManager {
        let mut manager = SfvManager {
            has_header: self.has_header,
            format: self.format,
            header: String::new(),
            root: self
                .root
                .clone()
                .unwrap_or_else(|| env::current_dir().unwrap_or_default()),
            files: vec![],
            file_indices: HashMap::new(),
            writer: UnsafeCell::new(self.writer.unwrap_or(Box::new(std::io::sink()))),
        };

        if let Some(old_data) = self.old_data {
            let Some(root) = self.root else {
                panic!("No root path specified.");
            };

            let mut format = self.format;
            let mut comment = String::new();

            let bsd_re = Regex::new(r"(.*?)\s*\((.*?)\)\s*=\s*([0-9a-fA-F]*)").unwrap();
            let info_re =
                Regex::new(r";\s*([+-]?\d+)\s*(\d+:\d+\.\d+ \d+-\d+-\d+)\s(( *).*)").unwrap();

            for line in old_data.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let mut possible_file = None;

                if Self::update(
                    &mut manager,
                    &mut possible_file,
                    try_parse_bsd(&bsd_re, &root, line),
                    &mut comment,
                    false,
                ) {
                    if format == crate::Format::Auto {
                        format = crate::Format::Bsd;
                    }
                    continue;
                }

                if Self::update(
                    &mut manager,
                    &mut possible_file,
                    try_parse_sfv(&root, line, &mut format),
                    &mut comment,
                    false,
                ) {
                    continue;
                }

                if Self::update(
                    &mut manager,
                    &mut possible_file,
                    try_parse_file_info(&info_re, &root, line),
                    &mut comment,
                    false,
                ) {
                    continue;
                }

                if Self::update(&mut manager, &mut None, possible_file, &mut comment, true) {
                    continue;
                }

                if let Some(c) = try_parse_comment(line) {
                    if manager.files.is_empty() {
                        manager.append_header_line(&c);
                    } else {
                        if !comment.is_empty() {
                            comment.push('\n');
                        }
                        comment.push_str(&c);
                    }

                    continue;
                }

                manager.files.push(ItemType::Error(line.to_owned()));
            }

            manager.format = format;
        }

        manager
    }
}

#[derive(Clone, Debug)]
pub struct FileInfo {
    pub path: Arc<Path>,
    pub relative_path: Arc<Path>,
    pub size: Option<u64>,
    pub modify_time: Option<NaiveDateTime>,
    pub digests: Option<HashMap<String, Option<HasherTag>>>,
    pub comment: Option<String>,
    pub meta: Option<Metadata>,
}

#[allow(clippy::large_enum_variant)]
pub enum ItemType {
    File(FileInfo),
    Error(String),
}

pub struct SfvManager {
    has_header: bool,
    format: crate::Format,
    header: String,
    root: PathBuf,
    files: Vec<ItemType>,
    file_indices: HashMap<Arc<Path>, usize>,
    writer: UnsafeCell<Box<dyn Write + Send>>,
}

impl SfvManager {
    pub fn format(&self) -> crate::Format {
        self.format
    }

    pub fn set_format(&mut self, format: crate::Format) {
        self.format = format;
    }

    pub fn update(
        &mut self,
        path: Arc<Path>,
        size: Option<u64>,
        modify_time: Option<NaiveDateTime>,
        digests: Option<impl Iterator<Item = (String, Option<HasherTag>)>>,
    ) {
        let digests = digests.map(|d| d.map(|(d, t)| (d.to_ascii_lowercase(), t)).collect());

        let file_index = self.file_indices.get_mut(&path);
        let Some(file_index) = file_index else {
            let rpath = path.strip_prefix(&self.root).unwrap_or(&path);
            self.file_indices.insert(path.clone(), self.files.len());
            self.files.push(ItemType::File(FileInfo {
                path: path.clone(),
                relative_path: rpath.into(),
                size,
                modify_time,
                digests,
                comment: None,
                meta: path.metadata().ok(),
            }));

            return;
        };

        let file = match &mut self.files[*file_index] {
            ItemType::File(file) => file,
            ItemType::Error(_) => unreachable!(),
        };

        if let Some(size) = size {
            file.size = Some(size)
        }

        if let Some(modify_time) = modify_time {
            file.modify_time = Some(modify_time)
        }

        if let Some(digests) = digests {
            let old_digests = file.digests.get_or_insert_with(HashMap::new);
            old_digests.extend(digests);
        }
    }

    pub fn append_header_line(&mut self, text: &str) {
        self.header.push_str(text);
        self.header.push('\n');
    }

    pub fn append_file_comment_line(&mut self, path: &Arc<Path>, comment: &str) {
        let Some(file_index) = self.file_indices.get_mut(path) else {
            return;
        };

        let file = match &mut self.files[*file_index] {
            ItemType::File(file) => file,
            ItemType::Error(_) => unreachable!(),
        };

        let file_comment = file.comment.get_or_insert(String::new());

        file_comment.push_str(comment);
        file_comment.push('\n');
    }

    pub fn files(&self) -> &[ItemType] {
        &self.files
    }

    pub fn try_detect_format(&self) -> Option<crate::Format> {
        if self.format == crate::Format::Auto {
            if let Some(file) = self.files.iter().find_map(|f| match f {
                ItemType::File(f) => {
                    if f.digests.is_some() {
                        Some(f)
                    } else {
                        None
                    }
                }
                ItemType::Error(_) => None,
            }) {
                match file.digests.as_ref().unwrap().len() {
                    1 => Some(crate::Format::CoreUtils),
                    _ => Some(crate::Format::Sfv),
                }
            } else {
                None
            }
        } else {
            Some(self.format)
        }
    }

    pub fn try_swap_remove(&mut self, path: &Path) {
        let Some(index) = self.file_indices.remove(path) else {
            return;
        };

        self.files.swap_remove(index);
        let Some(ItemType::File(new_value)) = self.files.get(index) else {
            return;
        };

        *self.file_indices.get_mut(&new_value.path).unwrap() = index;
    }

    pub fn clear(&mut self) {
        self.files.clear();
        self.file_indices.clear();
    }

    pub fn try_output_file(&self, path: &Path) {
        let Some(index) = self.file_indices.get(path) else {
            return;
        };

        let Some(ItemType::File(file)) = self.files.get(*index) else {
            return;
        };
        self.try_output_file_inner(file, self.format);
    }

    fn try_output_file_inner(&self, file: &FileInfo, format: crate::Format) {
        let writer = unsafe { &mut *self.writer.get() };

        let Some(digests) = file.digests.as_ref() else {
            return;
        };

        let mut digests = digests.iter().collect::<Vec<_>>();
        digests.sort_unstable_by(|a, b| match a.1.cmp(b.1) {
            core::cmp::Ordering::Equal => a.0.len().cmp(&b.0.len()),
            ord => ord,
        });

        match format {
            crate::Format::Auto => self.try_output_file_inner(
                file,
                self.try_detect_format().unwrap_or(crate::Format::CoreUtils),
            ),
            crate::Format::CoreUtils => {
                for digest in digests {
                    writer.write_fmt(format_args!("{}  ", digest.0)).unwrap();
                }
                writer
                    .write_fmt(format_args!("{}\n", file.relative_path.display()))
                    .unwrap();
            }
            crate::Format::Sfv => {
                writer
                    .write_fmt(format_args!("{}", file.relative_path.display()))
                    .unwrap();
                for digest in digests {
                    writer.write_fmt(format_args!("  {}", digest.0)).unwrap();
                }
                writer.write_all("\n".as_bytes()).unwrap()
            }
            crate::Format::Bsd => {
                for digest in digests {
                    let tag = match digest.1 {
                        Some(tag) => tag_to_str(tag),
                        None => "Unknown",
                    };

                    writer
                        .write_fmt(format_args!(
                            "{} ({}) = {}\n",
                            tag,
                            file.relative_path.display(),
                            digest.0
                        ))
                        .unwrap();
                }
            }
        }
    }

    pub fn try_output(&self) {
        let writer = unsafe { &mut *self.writer.get() };

        const VERSION: &str = env!("CARGO_PKG_VERSION");
        let now = Local::now();

        let files: Vec<_> = self
            .files
            .iter()
            .map_while(|i| match i {
                ItemType::File(file) => Some(file),
                ItemType::Error(_) => None,
            })
            .collect();
        if self.has_header {
            if self.header.is_empty() {
                writer
                    .write_fmt(format_args!(
                        "; Generated by MHash v{VERSION} on {}\n; Written by Maboroshinokiseki - https://github.com/maboroshinokiseki/mhash\n;\n",
                        now.format("%Y-%m-%d at %H:%M.%S"), 
                    ))
                    .unwrap();
            } else {
                writer.write_all(self.header.as_bytes()).unwrap();
            }

            for file in &files {
                writer
                    .write_fmt(format_args!(
                        "; {:>12}  {} {}\n",
                        file.size
                            .unwrap_or_else(|| file.meta.as_ref().map_or(0, |m| m.len())),
                        file.modify_time
                            .unwrap_or_else(|| file.meta.as_ref().map_or(
                                NaiveDateTime::default(),
                                |m| m
                                    .modified()
                                    .map_or(DateTime::<Local>::default(), |t| {
                                        DateTime::<Local>::from(t)
                                    })
                                    .naive_local()
                            ))
                            .format("%H:%M.%S %Y-%m-%d"),
                        file.relative_path.display()
                    ))
                    .unwrap();
            }
        }

        let format = self.try_detect_format().unwrap_or(crate::Format::Sfv);

        for file in files {
            self.try_output_file_inner(file, format);
        }
    }

    pub fn sort(&mut self, sorts: &[crate::args::Sort]) {
        self.files.sort_unstable_by(|a, b| match a {
            ItemType::File(a_f) => match b {
                ItemType::File(b_f) => Self::sorter(a_f, b_f, sorts),
                ItemType::Error(_) => Ordering::Greater,
            },
            ItemType::Error(a_e) => match b {
                ItemType::File(_) => Ordering::Less,
                ItemType::Error(b_e) => a_e.cmp(b_e),
            },
        });

        for i in 0..self.files.len() {
            match &self.files[i] {
                ItemType::File(f) => {
                    *self.file_indices.get_mut(&f.path).unwrap() = i;
                }
                ItemType::Error(_) => {}
            }
        }
    }

    fn sorter(a: &FileInfo, b: &FileInfo, sorts: &[crate::args::Sort]) -> Ordering {
        if sorts.is_empty() {
            return Ordering::Equal;
        }

        let sort = sorts[0];
        let a_meta = a.meta.as_ref();
        let b_meta = b.meta.as_ref();

        let order = match sort {
            crate::args::Sort::Path => a.path.cmp(&b.path),
            crate::args::Sort::PathDec => a.path.cmp(&b.path).reverse(),
            crate::args::Sort::Atime => Self::cmp_meta_option(a_meta, b_meta, |a, b| {
                a.accessed()
                    .unwrap_or(SystemTime::UNIX_EPOCH)
                    .cmp(&b.accessed().unwrap_or(SystemTime::UNIX_EPOCH))
            }),
            crate::args::Sort::AtimeDec => Self::cmp_meta_option(a_meta, b_meta, |a, b| {
                a.accessed()
                    .unwrap_or(SystemTime::UNIX_EPOCH)
                    .cmp(&b.accessed().unwrap_or(SystemTime::UNIX_EPOCH))
                    .reverse()
            }),
            crate::args::Sort::Ctime => Self::cmp_meta_option(a_meta, b_meta, |a, b| {
                a.created()
                    .unwrap_or(SystemTime::UNIX_EPOCH)
                    .cmp(&b.created().unwrap_or(SystemTime::UNIX_EPOCH))
            }),
            crate::args::Sort::CtimeDec => Self::cmp_meta_option(a_meta, b_meta, |a, b| {
                a.created()
                    .unwrap_or(SystemTime::UNIX_EPOCH)
                    .cmp(&b.created().unwrap_or(SystemTime::UNIX_EPOCH))
                    .reverse()
            }),
            crate::args::Sort::Mtime => Self::cmp_meta_option(a_meta, b_meta, |a, b| {
                a.modified()
                    .unwrap_or(SystemTime::UNIX_EPOCH)
                    .cmp(&b.modified().unwrap_or(SystemTime::UNIX_EPOCH))
            }),
            crate::args::Sort::MtimeDec => Self::cmp_meta_option(a_meta, b_meta, |a, b| {
                a.modified()
                    .unwrap_or(SystemTime::UNIX_EPOCH)
                    .cmp(&b.modified().unwrap_or(SystemTime::UNIX_EPOCH))
                    .reverse()
            }),
            crate::args::Sort::Size => {
                Self::cmp_meta_option(a_meta, b_meta, |a, b| a.len().cmp(&b.len()))
            }
            crate::args::Sort::SizeDec => {
                Self::cmp_meta_option(a_meta, b_meta, |a, b| a.len().cmp(&b.len()).reverse())
            }
        };

        if order.is_eq() {
            Self::sorter(a, b, &sorts[1..])
        } else {
            order
        }
    }

    fn cmp_meta_option(
        a: Option<&Metadata>,
        b: Option<&Metadata>,
        f: impl FnOnce(&Metadata, &Metadata) -> Ordering,
    ) -> Ordering {
        let a_rank = match a {
            Some(_) => 1,
            None => 0,
        };

        let b_rank = match b {
            Some(_) => 1,
            None => 0,
        };

        if a_rank == 1 && b_rank == 1 {
            (f)(a.unwrap(), b.unwrap())
        } else {
            a_rank.cmp(&b_rank)
        }
    }
}

// Format: hashname(filename)=digest
fn try_parse_bsd(re: &Regex, root: &Path, line: &str) -> Option<FileInfo> {
    let caps = re.captures(line)?;
    let hashes = Some({
        let mut map = HashMap::new();
        map.insert(
            caps.get(3)?.as_str().to_owned(),
            str_to_tag(caps.get(1)?.as_str()),
        );
        map
    });

    let rpath: Arc<Path> = PathBuf::from(caps.get(2)?.as_str()).into();
    let path = match rpath.is_absolute() {
        true => rpath.clone(),
        false => root.join(&rpath).into(),
    };
    Some(FileInfo {
        path: path.clone(),
        relative_path: rpath,
        size: None,
        modify_time: None,
        digests: hashes,
        comment: None,
        meta: path.metadata().ok(),
    })
}

// Format1: filename digest digest ...
// Format2: digest digest ... filename
fn try_parse_sfv(root: &Path, line: &str, format: &mut crate::Format) -> Option<FileInfo> {
    let mut possible_file = None;
    for (index, _) in line.match_indices(' ') {
        let left = &line[..index];
        let right = &line[(index + 1)..];
        if let (_valid_digest @ true, valid_path, file_info) =
            try_parse_sfv_inner(root, left, right)
        {
            if valid_path && file_info.is_some() {
                if *format == crate::Format::Auto {
                    *format = crate::Format::Sfv;
                }
                return file_info;
            }
            possible_file = possible_file.or(file_info);
        }
        if let (_valid_digest @ true, valid_path, file_info) =
            try_parse_sfv_inner(root, right, left)
        {
            if valid_path && file_info.is_some() {
                if *format == crate::Format::Auto {
                    *format = crate::Format::CoreUtils;
                }
                return file_info;
            }
            possible_file = possible_file.or(file_info);
        }
    }

    possible_file.map(|p| {
        let filename = p.relative_path.to_string_lossy();
        let filename = filename.trim();

        let path = match p.relative_path.is_absolute() {
            true => p.relative_path.clone(),
            false => root.join(filename).into(),
        };

        FileInfo {
            path,
            relative_path: PathBuf::from(filename).into(),
            size: p.size,
            modify_time: p.modify_time,
            digests: p.digests,
            comment: p.comment,
            meta: None,
        }
    })
}

fn try_parse_sfv_inner(
    root: &Path,
    filename: &str,
    digests: &str,
) -> (bool, bool, Option<FileInfo>) {
    let valid_hash = is_hex_with_whitespace_str(digests);

    if !valid_hash {
        return (valid_hash, false, None);
    }

    let rpath: Arc<Path> = PathBuf::from(filename).into();
    let path: Arc<Path> = match rpath.is_absolute() {
        true => rpath.clone(),
        false => root.join(&rpath).into(),
    };
    let valid_path = path.exists();

    let digests = digests
        .split_whitespace()
        .map(|s| (s.to_owned(), None))
        .collect();

    (
        valid_hash,
        valid_path,
        Some(FileInfo {
            path: path.clone(),
            relative_path: rpath,
            size: None,
            modify_time: None,
            digests: Some(digests),
            comment: None,
            meta: path.metadata().ok(),
        }),
    )
}

// Format: ; size_in_bytes hh:mm.ss yyyy-mm-dd filename
fn try_parse_file_info(re: &Regex, root: &Path, line: &str) -> Option<FileInfo> {
    let caps = re.captures(line)?;
    let size = caps.get(1)?;
    let modify_time = caps.get(2)?;
    let filename = caps.get(3)?;
    let rpath: Arc<Path> = PathBuf::from(filename.as_str()).into();
    let path = match rpath.is_absolute() {
        true => rpath.clone(),
        false => root.join(&rpath).into(),
    };

    Some(FileInfo {
        path: path.clone(),
        relative_path: rpath,
        size: size.as_str().parse::<u64>().ok(),
        modify_time: NaiveDateTime::parse_from_str(modify_time.as_str(), "%H:%M.%S %Y-%m-%d").ok(),
        digests: None,
        comment: None,
        meta: path.metadata().ok(),
    })
}

// Format: ;.*
fn try_parse_comment(line: &str) -> Option<String> {
    let c = line.as_bytes().first().unwrap_or(&0);
    if *c == b';' {
        Some(line.to_owned())
    } else {
        None
    }
}

fn is_hex_with_whitespace_str(str: &str) -> bool {
    let mut have_hex = false;
    for c in str.chars() {
        if c.is_ascii_hexdigit() {
            have_hex = true;
        } else if !c.is_whitespace() {
            return false;
        }
    }

    have_hex
}

fn str_to_tag(str: &str) -> Option<HasherTag> {
    let str = str.to_uppercase();
    match str.as_str() {
        "CRC32" => Some(HasherTag::CRC32),
        "CRC32C" => Some(HasherTag::CRC32C),
        "MD2" => Some(HasherTag::MD2),
        "MD4" => Some(HasherTag::MD4),
        "MD5" => Some(HasherTag::MD5),
        "SHA1" => Some(HasherTag::SHA1),
        "SHA224" => Some(HasherTag::SHA2_224),
        "SHA256" => Some(HasherTag::SHA2_256),
        "SHA384" => Some(HasherTag::SHA2_384),
        "SHA512" => Some(HasherTag::SHA2_512),
        "SHA3-224" => Some(HasherTag::SHA3_224),
        "SHA3-256" => Some(HasherTag::SHA3_256),
        "SHA3-384" => Some(HasherTag::SHA3_384),
        "SHA3-512" => Some(HasherTag::SHA3_512),
        _ => None,
    }
}
