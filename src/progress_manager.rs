use std::collections::HashMap;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use libmhash::hasher_server::Identifier;

// hashing:   [filename][hashname][progress/hash]
// chekcking: [filename][hash][progress/hashname matched/no matches]

pub struct ProgressManager {
    progress_groups: HashMap<Identifier, ProgressGroup>,
    multi_progress: MultiProgress,
    max_tag_width: Option<usize>,
    progressing_style: ProgressStyle,
    message_only_style: ProgressStyle,
}

pub struct ProgressGroup {
    identifier: Identifier,
    tag_width: usize,
    progress_bars: HashMap<String, ProgressBar>,
    message_only_style: ProgressStyle,
}

impl ProgressManager {
    pub fn new(max_tag_width: Option<usize>) -> Self {
        Self {
            progress_groups: HashMap::new(),
            multi_progress: MultiProgress::new(),
            max_tag_width,
            progressing_style: ProgressStyle::with_template("{msg}[{wide_bar}]").unwrap(),
            message_only_style: ProgressStyle::with_template("{msg}").unwrap(),
        }
    }

    pub fn get_or_insert(
        &mut self,
        identifier: Identifier,
        length: u64,
        tags: impl Iterator<Item = impl AsRef<str>> + Clone,
    ) -> &mut ProgressGroup {
        self.progress_groups
            .entry(identifier.clone())
            .or_insert_with(|| {
                ProgressGroup::new(
                    identifier,
                    length,
                    tags,
                    self.max_tag_width,
                    &self.multi_progress,
                    self.progressing_style.clone(),
                    self.message_only_style.clone(),
                )
            })
    }

    pub fn get(&mut self, identifier: &Identifier) -> &mut ProgressGroup {
        self.progress_groups.get_mut(identifier).unwrap()
    }

    pub fn insert_error(&mut self, identifier: &Identifier, message: &str) {
        let pg = self.get_or_insert(identifier.clone(), 1, ["ERROR"].iter());
        pg.complete_all_hash(message);
    }

    pub fn complete_file(&mut self, identifier: &Identifier, message: &str) {
        let progress_group = self.progress_groups.get_mut(identifier);
        match progress_group {
            Some(pg) => pg.complete_all_hash(message),
            None => {
                let pb = self.multi_progress.add(ProgressBar::new(0));
                pb.set_style(self.message_only_style.clone());
                pb.set_message(format!("[{}][{}]", identifier, message));
            }
        }
    }
}

impl ProgressGroup {
    fn new(
        identifier: Identifier,
        length: u64,
        tags: impl Iterator<Item = impl AsRef<str>> + Clone,
        max_tag_width: Option<usize>,
        multi_progress: &MultiProgress,
        progressing_style: ProgressStyle,
        message_only_style: ProgressStyle,
    ) -> Self {
        let mut progress_bars = HashMap::new();
        let tag_width = tags
            .clone()
            .map(|t| t.as_ref().len())
            .max()
            .unwrap()
            .clamp(0, max_tag_width.unwrap_or(usize::MAX));

        for tag in tags {
            let pb = multi_progress.add(ProgressBar::new(length));
            pb.set_style(progressing_style.clone());
            pb.set_message(format!(
                "[{}][{}]",
                identifier,
                crate::helper::ascii_string_normalize(tag.as_ref(), tag_width)
            ));
            progress_bars.insert(tag.as_ref().to_owned(), pb);
        }

        Self {
            identifier,
            tag_width,
            progress_bars,
            message_only_style,
        }
    }

    pub fn complete_hash(&mut self, tag: &str, message: &str) {
        let progress_bar = self.progress_bars.get_mut(tag).unwrap();

        if progress_bar.is_finished() {
            return;
        }

        let msg = format!(
            "[{}][{}][{}]",
            self.identifier,
            crate::helper::ascii_string_normalize(tag, self.tag_width),
            message,
        );

        progress_bar.set_style(self.message_only_style.clone());
        progress_bar.finish_with_message(msg);
    }

    pub fn complete_all_hash(&mut self, message: &str) {
        for (tag, progress_bar) in &self.progress_bars {
            if progress_bar.is_finished() {
                continue;
            }

            let msg = format!(
                "[{}][{}][{}]",
                self.identifier,
                crate::helper::ascii_string_normalize(tag, self.tag_width),
                message,
            );

            progress_bar.set_style(self.message_only_style.clone());
            progress_bar.finish_with_message(msg);
        }
    }

    pub fn set_position(&mut self, tag: &str, position: u64) {
        let pb = self.progress_bars.get_mut(tag).unwrap();
        pb.set_position(position);
    }

    pub fn set_length(&mut self, tag: &str, length: u64) {
        let pb = self.progress_bars.get_mut(tag).unwrap();
        pb.set_length(length);
    }

    pub fn inc(&mut self, tag: &str, delta: u64) {
        let pb = self.progress_bars.get_mut(tag).unwrap();
        pb.inc(delta);
    }
}
