//! A lossless dotenv model: a [`Document`] round-trips byte for byte, and
//! editing an entry rewrites only that entry's value bytes.
//!
//! `Debug` impls show key names, never values.

use std::fmt;
use std::ops::Range;

mod parse;
mod render;

pub use parse::is_valid_key;

use parse::{
    enclosed_assignments, opens_unterminated_quote, parse_line, swallowed_assignment,
    trailing_bytes_after_quote, unescape,
};
use render::render_value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quote {
    /// `KEY=value`
    None,
    /// `KEY='value'` — no escape processing.
    Single,
    /// `KEY="value"` — backslash escapes are expanded.
    Double,
}

#[derive(Clone)]
pub struct Entry {
    /// Includes the line terminator; a quoted value may span several lines.
    raw: String,
    key: String,
    /// Range inside `raw`, quotes included.
    value_span: Range<usize>,
    quote: Quote,
}

impl Entry {
    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> String {
        let text = &self.raw[self.value_span.clone()];
        match self.quote {
            Quote::None => text.to_string(),
            Quote::Single => text[1..text.len() - 1].to_string(),
            Quote::Double => unescape(&text[1..text.len() - 1]),
        }
    }

    pub fn raw_value(&self) -> &str {
        &self.raw[self.value_span.clone()]
    }

    /// `KEY=v # note` gives `# note`, without the line terminator.
    pub fn inline_comment(&self) -> Option<&str> {
        let trailing = self.raw[self.value_span.end..].trim_end_matches(['\r', '\n']);
        let trimmed = trailing.trim_start();
        trimmed.starts_with('#').then_some(trimmed)
    }

    /// Non-empty means a stray quote probably swallowed real variables into this value.
    pub fn enclosed_assignments(&self) -> Vec<&str> {
        enclosed_assignments(self.raw_value())
    }

    fn set(&mut self, value: &str) {
        let (rendered, quote) = render_value(value, self.quote);
        self.raw.replace_range(self.value_span.clone(), &rendered);
        self.value_span = self.value_span.start..self.value_span.start + rendered.len();
        self.quote = quote;
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("key", &self.key)
            .field("quote", &self.quote)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
pub struct Removed {
    pub assignments: usize,
    pub kept_comments: Vec<String>,
}

impl Removed {
    pub fn any(&self) -> bool {
        self.assignments > 0
    }
}

#[derive(Clone)]
pub enum Line {
    Blank(String),
    Comment(String),
    Entry(Entry),
    /// Anything uninterpreted (malformed assignment, unterminated quote), kept verbatim.
    Other(String),
}

impl Line {
    pub fn raw(&self) -> &str {
        match self {
            Line::Blank(raw) | Line::Comment(raw) | Line::Other(raw) => raw,
            Line::Entry(entry) => &entry.raw,
        }
    }
}

impl fmt::Debug for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Line::Blank(_) => f.write_str("Blank"),
            Line::Comment(_) => f.write_str("Comment"),
            Line::Other(_) => f.write_str("Other"),
            Line::Entry(entry) => entry.fmt(f),
        }
    }
}

#[derive(Clone, Default)]
pub struct Document {
    bom: bool,
    lines: Vec<Line>,
    /// For added lines: CRLF only if the file already uses it.
    newline: &'static str,
}

impl Document {
    pub fn new() -> Self {
        Document {
            bom: false,
            lines: Vec::new(),
            newline: "\n",
        }
    }

    /// Never fails: anything unrecognised is kept verbatim.
    pub fn parse(input: &str) -> Self {
        let (bom, body) = match input.strip_prefix('\u{feff}') {
            Some(rest) => (true, rest),
            None => (false, input),
        };
        let newline = if body.contains("\r\n") { "\r\n" } else { "\n" };

        let mut lines = Vec::new();
        let mut pos = 0;
        while pos < body.len() {
            let (line, next) = parse_line(body, pos);
            lines.push(line);
            debug_assert!(next > pos, "parse_line must make progress");
            pos = next;
        }

        Document {
            bom,
            lines,
            newline,
        }
    }

    pub fn lines(&self) -> &[Line] {
        &self.lines
    }

    /// Duplicates included.
    pub fn entries(&self) -> impl DoubleEndedIterator<Item = &Entry> {
        self.lines.iter().filter_map(|line| match line {
            Line::Entry(entry) => Some(entry),
            _ => None,
        })
    }

    /// The last assignment wins, as when a shell sources the file.
    pub fn get(&self, key: &str) -> Option<String> {
        self.entry(key).map(Entry::value)
    }

    pub fn entry(&self, key: &str) -> Option<&Entry> {
        self.entries().rfind(|entry| entry.key == key)
    }

    fn entries_mut<'a>(&'a mut self, key: &'a str) -> impl Iterator<Item = &'a mut Entry> {
        self.lines.iter_mut().filter_map(move |line| match line {
            Line::Entry(entry) if entry.key == key => Some(entry),
            _ => None,
        })
    }

    /// Rewrites every assignment of `key`: a shadowed duplicate would otherwise
    /// keep the plaintext the write was meant to replace.
    pub fn set_value(&mut self, key: &str, value: &str) -> usize {
        let mut changed = 0;
        for entry in self.entries_mut(key) {
            entry.set(value);
            changed += 1;
        }
        changed
    }

    pub fn assignment_count(&self, key: &str) -> usize {
        self.entries().filter(|entry| entry.key == key).count()
    }

    /// The caller must ensure `key` is a valid variable name.
    pub fn insert(&mut self, key: &str, value: &str) {
        self.terminate_last_line();
        let (rendered, quote) = render_value(value, Quote::None);
        let raw = format!("{key}={rendered}{}", self.newline);
        let start = key.len() + 1;
        self.lines.push(Line::Entry(Entry {
            key: key.to_string(),
            value_span: start..start + rendered.len(),
            quote,
            raw,
        }));
    }

    /// The most serious problem, not the first: an earlier advisory must not
    /// mask a later fatal one.
    pub fn quote_problem(&self) -> Option<QuoteProblem> {
        let problems = self.quote_problems();
        problems
            .iter()
            .find(|problem| problem.is_fatal())
            .or_else(|| problems.first())
            .cloned()
    }

    /// Every stray-quote problem, in line order.
    pub fn quote_problems(&self) -> Vec<QuoteProblem> {
        let mut problems = Vec::new();
        let mut number = 1;
        for line in &self.lines {
            match line {
                Line::Other(raw) if opens_unterminated_quote(raw) => {
                    problems.push(QuoteProblem::Unterminated { line: number });
                }
                Line::Other(raw) => {
                    if let Some(key) = trailing_bytes_after_quote(raw) {
                        problems.push(QuoteProblem::TrailingAfterQuote { line: number, key });
                    }
                }
                Line::Entry(entry) => {
                    if let Some(swallowed) = swallowed_assignment(&entry.value()) {
                        problems.push(QuoteProblem::SwallowedAssignment {
                            line: number,
                            key: entry.key().to_string(),
                            swallowed,
                        });
                    }
                }
                _ => {}
            }
            // A quoted entry may span several physical lines.
            number += line.raw().matches('\n').count().max(1);
        }
        problems
    }

    /// `f` returns `Some(new)` to replace a value. Duplicates are visited too,
    /// or encrypt-in-place would leave a plaintext copy behind.
    pub fn map_values<E>(
        &mut self,
        mut f: impl FnMut(&str, &str) -> Result<Option<String>, E>,
    ) -> Result<usize, E> {
        let mut changed = 0;
        for line in &mut self.lines {
            let Line::Entry(entry) = line else { continue };
            let key = entry.key.clone();
            if let Some(replacement) = f(&key, &entry.value())? {
                entry.set(&replacement);
                changed += 1;
            }
        }
        Ok(changed)
    }

    pub fn upsert(&mut self, key: &str, value: &str) {
        if self.set_value(key, value) == 0 {
            self.insert(key, value);
        }
    }

    /// An inline comment on a removed line is kept as its own line: the user
    /// wrote it and did not ask for it gone.
    pub fn remove(&mut self, key: &str) -> Removed {
        let mut removed = Removed::default();
        let newline = self.newline;
        let mut kept = Vec::with_capacity(self.lines.len());
        for line in std::mem::take(&mut self.lines) {
            match line {
                Line::Entry(entry) if entry.key == key => {
                    removed.assignments += 1;
                    if let Some(comment) = entry.inline_comment() {
                        removed.kept_comments.push(comment.to_string());
                        kept.push(Line::Comment(format!("{comment}{newline}")));
                    }
                }
                other => kept.push(other),
            }
        }
        self.lines = kept;
        removed
    }

    fn terminate_last_line(&mut self) {
        let newline = self.newline;
        let Some(last) = self.lines.last_mut() else {
            return;
        };
        let raw = match last {
            Line::Blank(raw) | Line::Comment(raw) | Line::Other(raw) => raw,
            Line::Entry(entry) => &mut entry.raw,
        };
        if !raw.ends_with('\n') {
            raw.push_str(newline);
        }
    }
}

impl fmt::Display for Document {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.bom {
            f.write_str("\u{feff}")?;
        }
        for line in &self.lines {
            f.write_str(line.raw())?;
        }
        Ok(())
    }
}

impl fmt::Debug for Document {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Document")
            .field("bom", &self.bom)
            .field("lines", &self.lines.len())
            .field("keys", &self.entries().map(Entry::key).collect::<Vec<_>>())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuoteProblem {
    /// Fatal: appending a quoted value would pair with it and swallow every entry in between.
    Unterminated { line: usize },
    /// A multi-line quoted value containing what reads as an assignment.
    /// A heuristic a genuine value can trip, so it only warns.
    SwallowedAssignment {
        line: usize,
        key: String,
        /// A fragment of a possibly secret value: never print it.
        swallowed: String,
    },
    /// `API_KEY='super'password`. Fatal: rewriting the quoted half would leave
    /// the tail on disk in cleartext.
    TrailingAfterQuote { line: usize, key: String },
}

impl QuoteProblem {
    /// 1-based.
    pub fn line(&self) -> usize {
        match self {
            QuoteProblem::Unterminated { line }
            | QuoteProblem::SwallowedAssignment { line, .. }
            | QuoteProblem::TrailingAfterQuote { line, .. } => *line,
        }
    }

    /// Whether a writer must refuse the file rather than warn.
    pub fn is_fatal(&self) -> bool {
        match self {
            QuoteProblem::Unterminated { .. } | QuoteProblem::TrailingAfterQuote { .. } => true,
            QuoteProblem::SwallowedAssignment { .. } => false,
        }
    }
}

impl fmt::Display for QuoteProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuoteProblem::Unterminated { line } => {
                write!(f, "line {line} opens a quote that is never closed")
            }
            // `swallowed` may be a fragment of a secret.
            QuoteProblem::SwallowedAssignment {
                line,
                key,
                swallowed: _,
            } => write!(
                f,
                "the quoted value of '{key}' starting at line {line} spans several lines and \
                 contains what reads as another assignment, so a stray quote has probably \
                 swallowed a variable"
            ),
            QuoteProblem::TrailingAfterQuote { line, key } => write!(
                f,
                "line {line} assigns '{key}' a quoted value with more text after the closing \
                 quote, which belongs to neither the value nor a comment, so '{key}' is not \
                 read at all; quote the whole value or remove the stray quotes"
            ),
        }
    }
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_quoted_value_with_bytes_after_it_is_not_an_assignment() {
        for source in [
            "API_KEY='super'password\n",
            "API_KEY=\"super\"password\n",
            "export API_KEY='super'password\n",
            "API_KEY='super' password\n",
            "API_KEY='super'\t'more'\n",
            "API_KEY=\"line one\nline two\"password\n",
            "API_KEY='line one\nline two'password\n",
            "API_KEY=\"line one\nline two\" password\n",
        ] {
            let document = Document::parse(source);
            assert_eq!(
                document.get("API_KEY"),
                None,
                "{source:?} was read as an assignment"
            );
            assert_eq!(document.to_string(), source);
            assert!(
                matches!(
                    document.quote_problem(),
                    Some(QuoteProblem::TrailingAfterQuote { line: 1, ref key }) if key == "API_KEY"
                ),
                "{source:?}: {:?}",
                document.quote_problem()
            );
        }
    }

    #[test]
    fn a_multiline_value_partly_outside_its_quotes_cannot_be_rewritten_in_place() {
        let mut document =
            Document::parse("PRIVATE_KEY=\"line one\nline two\"SECRETTAIL\nPORT=80\n");
        assert_eq!(document.set_value("PRIVATE_KEY", "gitguardian:QUJD"), 0);
        assert!(
            document.to_string().contains("SECRETTAIL"),
            "{}",
            document.to_string()
        );
    }

    #[test]
    fn a_fatal_quote_problem_is_not_masked_by_an_earlier_advisory() {
        let document =
            Document::parse("CERT=\"line\nINNER=value\nend\"\nAPI_KEY='super'password\n");
        let problems = document.quote_problems();
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(matches!(
            problems[0],
            QuoteProblem::SwallowedAssignment { .. }
        ));
        let chosen = document.quote_problem().expect("a problem");
        assert!(chosen.is_fatal(), "{chosen:?}");
        assert!(
            matches!(chosen, QuoteProblem::TrailingAfterQuote { ref key, .. } if key == "API_KEY"),
            "{chosen:?}"
        );
    }

    #[test]
    fn the_swallowed_assignment_message_does_not_echo_a_fragment_of_the_value() {
        let document = Document::parse("NOTE=\"oops\nSWALLOWED_NAME=abc\nOTHER=\"\n");
        let problem = document.quote_problem().expect("a problem");
        let rendered = problem.to_string();
        assert!(rendered.contains("'NOTE'"), "{rendered}");
        assert!(rendered.contains("line 1"), "{rendered}");
        assert!(
            !rendered.contains("SWALLOWED_NAME"),
            "a fragment of the value leaked: {rendered}"
        );
    }

    #[test]
    fn a_quoted_value_followed_by_nothing_or_a_comment_is_still_an_assignment() {
        for (source, expected) in [
            ("API_KEY='super'\n", "super"),
            ("API_KEY='super'   \n", "super"),
            ("API_KEY='super' # rotated monthly\n", "super"),
            ("API_KEY='super'# no space\n", "super"),
            ("API_KEY=\"super\"\r\n", "super"),
            ("API_KEY='multi\nline'\n", "multi\nline"),
        ] {
            let document = Document::parse(source);
            assert_eq!(
                document.get("API_KEY").as_deref(),
                Some(expected),
                "{source:?}"
            );
            assert_eq!(document.quote_problem(), None, "{source:?}");
        }
    }

    #[test]
    fn a_malformed_quoted_line_is_preserved_and_not_rewritten() {
        let mut document = Document::parse("API_KEY='super'password\nPORT=80\n");
        document.upsert("API_KEY", "replacement");
        assert_eq!(
            document.to_string(),
            "API_KEY='super'password\nPORT=80\nAPI_KEY=replacement\n"
        );
    }

    #[test]
    fn the_last_duplicate_assignment_wins_when_reading() {
        let document = Document::parse("A=1\nA=2\nA=3\n");
        assert_eq!(document.get("A").as_deref(), Some("3"));
        assert_eq!(document.assignment_count("A"), 3);
    }

    #[test]
    fn set_value_rewrites_every_duplicate_assignment() {
        let mut document = Document::parse("A=1\nA=2\nA=3\n");
        assert_eq!(document.set_value("A", "4"), 3);
        assert_eq!(document.to_string(), "A=4\nA=4\nA=4\n");
    }

    #[test]
    fn set_value_leaves_no_earlier_plaintext_when_a_key_is_duplicated() {
        let mut document = Document::parse("API_KEY=old-plaintext\nB=1\nAPI_KEY=other-plaintext\n");
        document.set_value("API_KEY", "gitguardian:QUJD");
        let rendered = document.to_string();
        assert!(
            !rendered.contains("plaintext"),
            "an earlier assignment kept its cleartext: {rendered}"
        );
    }

    #[test]
    fn set_value_changes_only_that_entrys_value_bytes() {
        let source =
            "\u{feff}# header comment\r\n\r\nexport A=1   \r\nB=\"keep me\"\r\n\r\n# tail\r\nC=3";
        let mut document = Document::parse(source);
        assert_eq!(document.set_value("A", "changed"), 1);
        let expected = source.replace("export A=1   ", "export A=changed   ");
        assert_eq!(document.to_string(), expected);
    }

    #[test]
    fn unchanged_entries_keep_their_exact_bytes() {
        let source = "CIPHER=gitguardian:QUJDREVGRw\nOTHER=1\n";
        let mut document = Document::parse(source);
        document.set_value("OTHER", "2");
        assert!(
            document
                .to_string()
                .contains("CIPHER=gitguardian:QUJDREVGRw\n")
        );
    }

    #[test]
    fn insert_appends_and_adds_a_missing_final_newline() {
        let mut document = Document::parse("A=1");
        document.insert("B", "2");
        assert_eq!(document.to_string(), "A=1\nB=2\n");
    }

    #[test]
    fn insert_uses_the_documents_line_ending() {
        let mut document = Document::parse("A=1\r\n");
        document.insert("B", "2");
        assert_eq!(document.to_string(), "A=1\r\nB=2\r\n");
    }

    #[test]
    fn upsert_updates_in_place_or_appends() {
        let mut document = Document::parse("# comment\nA=1\n");
        document.upsert("A", "2");
        document.upsert("B", "3");
        assert_eq!(document.to_string(), "# comment\nA=2\nB=3\n");
    }

    #[test]
    fn remove_drops_every_assignment_of_a_key() {
        let mut document = Document::parse("A=1\n# keep\nA=2\nB=3\n");
        let removed = document.remove("A");
        assert_eq!(removed.assignments, 2);
        assert!(removed.kept_comments.is_empty());
        assert!(!document.remove("A").any());
        assert_eq!(document.to_string(), "# keep\nB=3\n");
    }

    #[test]
    fn remove_keeps_an_inline_comment_as_its_own_line() {
        let mut document = Document::parse("A=1 # obtain from the owner\nB=2\n");
        let removed = document.remove("A");
        assert_eq!(removed.kept_comments, ["# obtain from the owner"]);
        assert_eq!(document.to_string(), "# obtain from the owner\nB=2\n");
    }

    #[test]
    fn remove_keeps_an_inline_comment_on_a_quoted_value_too() {
        let mut document = Document::parse("A='one' # note\r\nB=2\r\n");
        document.remove("A");
        assert_eq!(document.to_string(), "# note\r\nB=2\r\n");
    }

    #[test]
    fn an_entry_reports_the_assignments_swallowed_into_its_value() {
        let document = Document::parse("A=\"oops\nB=keepme\nc=fine\"\nD=1\n");
        let entry = document.entry("A").expect("A parses as one entry");
        assert_eq!(entry.enclosed_assignments(), ["B", "c"]);
        // Base64 padding ends a line in `=` behind a valid key name; not an assignment.
        let document = Document::parse(
            "KEY=\"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw==\n-----END PRIVATE KEY-----\"\n",
        );
        let entry = document.entry("KEY").expect("KEY parses as one entry");
        assert!(
            entry.enclosed_assignments().is_empty(),
            "{:?}",
            entry.enclosed_assignments()
        );
    }

    #[test]
    fn updating_a_value_keeps_its_inline_comment() {
        let mut document = Document::parse("# header\nAPI_KEY=old # rotated monthly\nB=2\n");
        assert_eq!(document.set_value("API_KEY", "new"), 1);
        assert_eq!(
            document.to_string(),
            "# header\nAPI_KEY=new # rotated monthly\nB=2\n"
        );
        assert_eq!(document.get("API_KEY").as_deref(), Some("new"));
    }

    #[test]
    fn raw_value_exposes_the_bytes_as_written() {
        let document = Document::parse("A=\"quoted\"\n");
        assert_eq!(document.entry("A").unwrap().raw_value(), "\"quoted\"");
    }

    #[test]
    fn debug_output_never_contains_a_value() {
        let document = Document::parse("SECRET=fake-placeholder-value\n");
        let debug = format!("{document:?}");
        assert!(debug.contains("SECRET"), "{debug}");
        assert!(!debug.contains("fake-placeholder-value"), "{debug}");

        let entry_debug = format!("{:?}", document.entry("SECRET").unwrap());
        assert!(
            !entry_debug.contains("fake-placeholder-value"),
            "{entry_debug}"
        );

        let line_debug = format!("{:?}", document.lines());
        assert!(
            !line_debug.contains("fake-placeholder-value"),
            "{line_debug}"
        );
    }
}
