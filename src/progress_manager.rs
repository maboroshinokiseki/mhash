use std::collections::{HashMap, VecDeque};

use kdam::{term, tqdm, Bar, BarExt};
use libmhash::hasher_server::Identifier;
use unicode_truncate::UnicodeTruncateStr;

pub const MAX_TAG_LENGTH: usize = 16;

// hashing:   [filename][hashname][progress/hash]
// chekcking: [filename][hash][progress/hashname matched/no matches]

pub struct ProgressManager {
    progress_group_indices: HashMap<Identifier, usize>,
    progress_groups: VecDeque<ProgressGroup>,
    max_id_width: Option<usize>,
    max_tag_width: Option<usize>,
    active_rows: usize,
    total_rows: u16,
}

pub struct ProgressGroup {
    identifier: Identifier,
    id_width: usize,
    tag_width: usize,
    progress_bar_indices: HashMap<String, usize>,
    progress_bars: Vec<ProgressBar>,
}

pub struct ProgressBar {
    bar: Bar,
    completed: bool,
    total: u64,
    counter: u64,
}

impl ProgressManager {
    pub fn new(max_tag_width: Option<usize>) -> Self {
        let terminal_width = terminal_size::terminal_size()
            .map(|(w, _)| w.0)
            .unwrap_or(80) as usize;
        // terminal width sub MAX_TAG_LENGTH sub [][][] sub progressbar and possible message length sub prepend ...
        let max_id_width = terminal_width
            .saturating_sub(max_tag_width.unwrap_or(MAX_TAG_LENGTH))
            .saturating_sub(6)
            .saturating_sub(16)
            .saturating_sub(3);
        let max_id_width = match max_id_width {
            0 => None,
            _ => Some(max_id_width),
        };
        Self {
            progress_group_indices: HashMap::new(),
            progress_groups: VecDeque::new(),
            max_id_width,
            max_tag_width,
            active_rows: 0,
            total_rows: terminal_size::terminal_size()
                .map(|(_, h)| h.0)
                .unwrap_or(3)
                - 2,
        }
    }

    pub fn get_or_insert(
        &mut self,
        identifier: Identifier,
        length: u64,
        tags: impl Iterator<Item = impl AsRef<str>> + Clone,
    ) -> &mut ProgressGroup {
        let mut inserted = false;
        let index = self
            .progress_group_indices
            .entry(identifier.clone())
            .or_insert_with(|| {
                self.progress_groups.push_back(ProgressGroup::new(
                    identifier,
                    length,
                    tags,
                    self.max_id_width,
                    self.max_tag_width,
                ));

                inserted = true;

                self.progress_groups.len() - 1
            });

        let item = self.progress_groups.get_mut(*index).unwrap();

        if !inserted {
            return item;
        }

        for pb in &mut item.progress_bars {
            pb.bar.position = self.active_rows as u16;
            if self.total_rows > pb.bar.position {
                self.active_rows += 1;
                pb.bar.refresh().unwrap();
            } else {
                pb.bar.disable = true;
            }
        }

        item
    }

    pub fn refresh(&mut self) -> std::io::Result<()> {
        let mut completed_group_count = 0;
        for pg in &mut self.progress_groups {
            if !pg.progress_bars.iter().all(|pb| pb.completed) {
                break;
            }

            completed_group_count += 1;

            for pb in &mut pg.progress_bars {
                let bar = &mut pb.bar;

                let text = bar.render();
                bar.writer.print(format!("\r{}\n", text).as_bytes())?;

                bar.clear()?;
                bar.disable = true;
            }
        }

        if completed_group_count != 0 {
            for _ in 0..completed_group_count {
                self.progress_groups.pop_front();
            }

            self.progress_group_indices
                .retain(|_, v| *v >= completed_group_count);

            for v in self.progress_group_indices.values_mut() {
                *v -= completed_group_count;
            }

            self.active_rows = 0;
            for pg in &mut self.progress_groups {
                if self.total_rows as usize <= self.active_rows {
                    break;
                }

                for pb in &mut pg.progress_bars {
                    pb.bar.position = self.active_rows as u16;
                    if self.total_rows > pb.bar.position {
                        self.active_rows += 1;
                        pb.bar.disable = false;
                        pb.bar.clear()?;
                        pb.bar.refresh()?;
                    } else {
                        pb.bar.disable = true;
                    }
                }
            }
        }

        if self
            .progress_groups
            .iter()
            .map(|g| g.progress_bars.len() as u64)
            .sum::<u64>()
            > self.active_rows as u64
        {
            term::Writer::Stderr
                .print_at(self.active_rows as u16, " ... (more hidden) ...".as_bytes())?;
        }

        Ok(())
    }

    pub fn try_get(&mut self, identifier: &Identifier) -> Option<&mut ProgressGroup> {
        let index = self.progress_group_indices.get(identifier)?;
        self.progress_groups.get_mut(*index)
    }

    pub fn insert_error(&mut self, identifier: &Identifier, message: &str) {
        let pg = self.get_or_insert(identifier.clone(), 1, ["ERROR"].iter());
        pg.complete_all_hash(message);
    }

    pub fn complete_file(&mut self, identifier: &Identifier, message: &str) {
        let index = self.progress_group_indices.get(identifier);

        match index {
            Some(index) => {
                let progress_group = &mut self.progress_groups[*index];
                progress_group.complete_all_hash(message);
            }
            None => {
                let id = identifier.to_string();
                let truncated_id = id
                    .unicode_truncate_start(self.max_id_width.unwrap_or(usize::MAX))
                    .0;

                term::Writer::Stderr
                    .print(
                        match id == truncated_id {
                            true => format!("[{}][{}]", id, message),
                            false => format!("[...{}][{}]", truncated_id, message),
                        }
                        .as_bytes(),
                    )
                    .unwrap();
            }
        }
    }
}

impl ProgressGroup {
    fn new(
        identifier: Identifier,
        length: u64,
        tags: impl Iterator<Item = impl AsRef<str>> + Clone,
        max_id_width: Option<usize>,
        max_tag_width: Option<usize>,
    ) -> Self {
        let tag_width = tags
            .clone()
            .map(|t| t.as_ref().len())
            .max()
            .unwrap()
            .clamp(0, max_tag_width.unwrap_or(usize::MAX));

        let id_width = max_id_width.unwrap_or(usize::MAX);

        let mut progress_bar_indices = HashMap::new();
        let mut progress_bars = Vec::new();

        for tag in tags {
            let id = identifier.to_string();
            let truncated_id = id.unicode_truncate_start(id_width).0;

            let pb = tqdm!(
                total = 10000,
                force_refresh = true,
                bar_format = "{desc suffix=''}[{animation}]",
                desc = match id == truncated_id {
                    true => format!(
                        "[{}][{}]",
                        id,
                        crate::helper::ascii_string_normalize(tag.as_ref(), tag_width)
                    ),
                    false => format!(
                        "[...{}][{}]",
                        truncated_id,
                        crate::helper::ascii_string_normalize(tag.as_ref(), tag_width)
                    ),
                }
            );

            progress_bar_indices.insert(tag.as_ref().to_owned(), progress_bars.len());
            progress_bars.push(ProgressBar {
                bar: pb,
                completed: false,
                total: length,
                counter: 0,
            });
        }

        Self {
            identifier,
            id_width,
            tag_width,
            progress_bar_indices,
            progress_bars,
        }
    }

    pub fn complete_hash(&mut self, tag: &str, message: &str) {
        let pbi = self.progress_bar_indices.get(tag).unwrap();
        let pb = &mut self.progress_bars[*pbi];

        if pb.completed {
            return;
        }

        let id = self.identifier.to_string();
        let truncated_id = id.unicode_truncate_start(self.id_width).0;

        let msg = match id == truncated_id {
            true => format!(
                "[{}][{}][{}]",
                id,
                crate::helper::ascii_string_normalize(tag, self.tag_width),
                message,
            ),
            false => format!(
                "[...{}][{}][{}]",
                truncated_id,
                crate::helper::ascii_string_normalize(tag, self.tag_width),
                message,
            ),
        };

        pb.bar.set_bar_format("{desc suffix=''}").unwrap();
        pb.bar.set_description(msg);
        if pb.bar.should_refresh() {
            pb.bar.clear().unwrap();
            pb.bar.refresh().unwrap();
        }
        pb.completed = true;
    }

    pub fn complete_all_hash(&mut self, message: &str) {
        for (tag, index) in &self.progress_bar_indices {
            let pb = &mut self.progress_bars[*index];
            if pb.completed {
                continue;
            }

            let id = self.identifier.to_string();
            let truncated_id = id.unicode_truncate_start(self.id_width).0;

            let msg = match id == truncated_id {
                true => format!(
                    "[{}][{}][{}]",
                    id,
                    crate::helper::ascii_string_normalize(tag, self.tag_width),
                    message,
                ),
                false => format!(
                    "[...{}][{}][{}]",
                    truncated_id,
                    crate::helper::ascii_string_normalize(tag, self.tag_width),
                    message,
                ),
            };

            pb.bar.set_bar_format("{desc suffix=''}").unwrap();
            pb.bar.set_description(msg);
            if pb.bar.should_refresh() {
                pb.bar.clear().unwrap();
                pb.bar.refresh().unwrap();
            }
            pb.completed = true;
        }
    }

    pub fn set_position(&mut self, tag: &str, position: u64) {
        let pbi = self.progress_bar_indices.get(tag).unwrap();
        let pb = &mut self.progress_bars[*pbi];
        pb.counter = position;
        pb.bar.counter = ((pb.counter as f64 / pb.total as f64) * 10000.0) as usize;
        pb.bar.update(0).unwrap();
    }

    pub fn set_length(&mut self, tag: &str, length: u64) {
        let pbi = self.progress_bar_indices.get(tag).unwrap();
        let pb = &mut self.progress_bars[*pbi];
        pb.total = length;
        pb.bar.counter = ((pb.counter as f64 / pb.total as f64) * 10000.0) as usize;
        pb.bar.update(0).unwrap();
    }

    pub fn inc(&mut self, tag: &str, delta: u64) {
        let pbi = self.progress_bar_indices.get(tag).unwrap();
        let pb = &mut self.progress_bars[*pbi];
        pb.counter += delta;
        pb.bar.counter = ((pb.counter as f64 / pb.total as f64) * 10000.0) as usize;
        pb.bar.update(0).unwrap();
    }
}
