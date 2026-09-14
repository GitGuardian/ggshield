//! A lossless, document-preserving dotenv model.
//!
//! Unlike a `KEY -> value` map, a [`Document`] keeps every byte of the file it
//! was parsed from: comments, blank-line runs, `export` prefixes, quoting
//! style, CRLF endings, a UTF-8 BOM, duplicate keys and a missing final
//! newline all survive a parse/serialise round trip untouched. Editing one
//! entry rewrites that entry's value bytes and nothing else, so a file the
//! user maintains by hand stays theirs — and ciphertext we did not re-encrypt
//! is preserved verbatim.
//!
//! Values are file content, so they may be secret: [`Document`],
//! [`Line`] and [`Entry`] deliberately have hand-written [`std::fmt::Debug`]
//! implementations that show key names and never a value.

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

/// How an entry's value is quoted in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quote {
    /// `KEY=value`
    None,
    /// `KEY='value'` — no escape processing.
    Single,
    /// `KEY="value"` — backslash escapes are expanded.
    Double,
}

/// One `KEY=value` assignment, with the exact bytes it occupies in the file.
#[derive(Clone)]
pub struct Entry {
    /// The entry's full text, including its line terminator. A quoted value
    /// may span several physical lines, in which case they are all here.
    raw: String,
    key: String,
    /// Byte range of the value *inside `raw`*, quotes included.
    value_span: Range<usize>,
    quote: Quote,
}

impl Entry {
    /// The variable name.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The value with quoting and escapes resolved.
    pub fn value(&self) -> String {
        let text = &self.raw[self.value_span.clone()];
        match self.quote {
            Quote::None => text.to_string(),
            Quote::Single => text[1..text.len() - 1].to_string(),
            Quote::Double => unescape(&text[1..text.len() - 1]),
        }
    }

    /// The value exactly as written, quotes and escapes included.
    pub fn raw_value(&self) -> &str {
        &self.raw[self.value_span.clone()]
    }

    /// The inline comment after the value, without its line terminator.
    ///
    /// `KEY=v # note` and `KEY='v' # note` both give `# note`; an entry with
    /// nothing but whitespace after its value gives `None`. The comment lives
    /// in `raw` outside `value_span` for both quoting styles, so this is the
    /// one accessor that can see it — [`Document::remove`] needs it to avoid
    /// destroying a note the user wrote.
    pub fn inline_comment(&self) -> Option<&str> {
        let trailing = self.raw[self.value_span.end..].trim_end_matches(['\r', '\n']);
        let trimmed = trailing.trim_start();
        trimmed.starts_with('#').then_some(trimmed)
    }

    /// Assignments written *inside* this entry's value.
    ///
    /// Non-empty means a stray quote has probably swallowed real variables into
    /// this entry, so removing it as one line would delete them too. See
    /// [`parse::enclosed_assignments`] for where the line is drawn — a PEM key
    /// is a legitimate multi-line value and must not look like this.
    pub fn enclosed_assignments(&self) -> Vec<&str> {
        enclosed_assignments(self.raw_value())
    }

    /// Replace the value, touching only the bytes of the value itself.
    ///
    /// The existing quoting style is kept when it can still represent the new
    /// value, so a hand-quoted entry does not silently change shape.
    fn set(&mut self, value: &str) {
        let (rendered, quote) = render_value(value, self.quote);
        self.raw.replace_range(self.value_span.clone(), &rendered);
        self.value_span = self.value_span.start..self.value_span.start + rendered.len();
        self.quote = quote;
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the value: entries hold secrets.
        f.debug_struct("Entry")
            .field("key", &self.key)
            .field("quote", &self.quote)
            .finish_non_exhaustive()
    }
}

/// What [`Document::remove`] took out.
#[derive(Debug, Default)]
pub struct Removed {
    /// How many assignments of the name were removed. More than one means the
    /// file assigned it repeatedly.
    pub assignments: usize,
    /// Inline comments that were kept as comment lines of their own.
    pub kept_comments: Vec<String>,
}

impl Removed {
    /// Whether anything was removed at all.
    pub fn any(&self) -> bool {
        self.assignments > 0
    }
}

/// One logical line of a dotenv file.
#[derive(Clone)]
pub enum Line {
    /// Empty or whitespace-only.
    Blank(String),
    /// A `#` comment.
    Comment(String),
    /// A `KEY=value` assignment.
    Entry(Entry),
    /// Anything we do not interpret (a malformed assignment, an unterminated
    /// quote, ...). Preserved verbatim so a round trip is still lossless.
    Other(String),
}

impl Line {
    /// The line's bytes, exactly as they appear in the file.
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

/// A parsed dotenv file that can be serialised back byte for byte.
#[derive(Clone, Default)]
pub struct Document {
    /// The file started with a UTF-8 BOM.
    bom: bool,
    lines: Vec<Line>,
    /// Line terminator used for lines we add: CRLF only if the file already
    /// uses it.
    newline: &'static str,
}

impl Document {
    /// An empty document, using `\n` line endings.
    pub fn new() -> Self {
        Document {
            bom: false,
            lines: Vec::new(),
            newline: "\n",
        }
    }

    /// Parse `input`. Never fails: anything unrecognised is kept verbatim.
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

    /// The lines, in file order.
    pub fn lines(&self) -> &[Line] {
        &self.lines
    }

    /// Every entry, in file order (duplicates included).
    pub fn entries(&self) -> impl DoubleEndedIterator<Item = &Entry> {
        self.lines.iter().filter_map(|line| match line {
            Line::Entry(entry) => Some(entry),
            _ => None,
        })
    }

    /// The value of `key`. When a key is assigned more than once the last
    /// assignment wins, matching how a shell sources the file.
    pub fn get(&self, key: &str) -> Option<String> {
        self.entry(key).map(Entry::value)
    }

    /// The last entry assigning `key`.
    pub fn entry(&self, key: &str) -> Option<&Entry> {
        self.entries().rfind(|entry| entry.key == key)
    }

    fn entries_mut<'a>(&'a mut self, key: &'a str) -> impl Iterator<Item = &'a mut Entry> {
        self.lines.iter_mut().filter_map(move |line| match line {
            Line::Entry(entry) if entry.key == key => Some(entry),
            _ => None,
        })
    }

    /// Update `key`'s value in place, returning how many assignments changed.
    ///
    /// **Every** assignment of `key` is rewritten, not just the last one a
    /// shell would use. A duplicated key is where the hazard lives: rewriting
    /// only the winner leaves the loser's value on disk, and for this provider
    /// the loser's value is the plaintext secret the write was supposed to
    /// replace. The file would read back correctly through [`Document::get`]
    /// while still carrying the cleartext it was meant to seal.
    ///
    /// [`Document::remove`] and [`Document::map_values`] already treat every
    /// assignment as real for the same reason.
    pub fn set_value(&mut self, key: &str, value: &str) -> usize {
        let mut changed = 0;
        for entry in self.entries_mut(key) {
            entry.set(value);
            changed += 1;
        }
        changed
    }

    /// How many times `key` is assigned.
    pub fn assignment_count(&self, key: &str) -> usize {
        self.entries().filter(|entry| entry.key == key).count()
    }

    /// Append a new `KEY=value` line at the end of the document.
    ///
    /// The caller is responsible for `key` being a valid variable name.
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

    /// The most serious stray-quote problem in the document, if there is one.
    ///
    /// A stray `"` does not corrupt the file — every byte survives a round trip
    /// — but it pairs with the next quote it can find, and everything between
    /// them collapses into one value. Variables silently disappear.
    ///
    /// There are two shapes, and they need different treatment; see
    /// [`QuoteProblem`].
    ///
    /// **The most serious, not the first.** Returning the first one found let a
    /// non-fatal [`QuoteProblem::SwallowedAssignment`] earlier in the file mask a
    /// fatal [`QuoteProblem::TrailingAfterQuote`] later in it: every writer
    /// matches on this one value, saw only an advisory, and went ahead — leaving
    /// the malformed line's cleartext on disk while reporting success.
    pub fn quote_problem(&self) -> Option<QuoteProblem> {
        let problems = self.quote_problems();
        problems
            .iter()
            .find(|problem| problem.is_fatal())
            .or_else(|| problems.first())
            .cloned()
    }

    /// Every stray-quote problem in the document, in line order.
    ///
    /// A file can have more than one, and they can be of different severities;
    /// a caller that *reports* problems rather than deciding on one should show
    /// them all.
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

    /// Rewrite every entry's value through `f`, touching nothing else.
    ///
    /// `f` receives each entry's name and resolved value and returns `Some(new)`
    /// to replace it or `None` to leave it exactly as it is. Every assignment is
    /// visited, duplicates included: a key assigned twice would otherwise keep
    /// one of its values, and for an encrypt-in-place pass that means leaving a
    /// plaintext secret behind.
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

    /// Set `key`, updating it in place if present and appending it otherwise.
    pub fn upsert(&mut self, key: &str, value: &str) {
        if self.set_value(key, value) == 0 {
            self.insert(key, value);
        }
    }

    /// Remove every assignment of `key`, returning whether any was removed.
    ///
    /// An inline comment on a removed line survives as a comment line of its
    /// own. The value is what the caller asked to destroy; the note beside it
    /// is text the user wrote and did not name, and for an encrypted value
    /// there is no way to get either back. An orphaned `# obtain from the
    /// break-glass owner` is a line they can delete in a second; the sentence
    /// itself may be the only copy.
    ///
    /// Returns `Removed` so a caller can report the comment it kept rather
    /// than leaving the user to find it.
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

    /// Give the last line a terminator, so an appended line starts on its own.
    ///
    /// This is the one edit that can change bytes outside an entry's value:
    /// a file with no final newline gains one when something is appended.
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
        // Key names only: values are file content and may be secret.
        f.debug_struct("Document")
            .field("bom", &self.bom)
            .field("lines", &self.lines.len())
            .field("keys", &self.entries().map(Entry::key).collect::<Vec<_>>())
            .finish()
    }
}

/// A stray quote, and what can safely be done about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuoteProblem {
    /// A line opens a quote that nothing closes before the end of the file.
    ///
    /// Unambiguously broken, and *appending* is what makes it worse: a new
    /// quoted value gives the stray quote the partner it was missing, and every
    /// entry in between vanishes into one value. A writer should refuse.
    Unterminated { line: usize },
    /// A quoted value spans several lines and contains what reads as another
    /// assignment — the signature of a stray quote that has already paired with
    /// a later, legitimate one.
    ///
    /// The damage is already done at parse time, and it is a heuristic: a
    /// genuine multi-line value may contain `KEY=` quite legitimately. So this
    /// warns and never blocks.
    SwallowedAssignment {
        line: usize,
        /// The entry whose value grew.
        key: String,
        /// The assignment found inside that value.
        ///
        /// **A fragment of a value, so never print it.** It was extracted from
        /// *inside* `key`'s value, and if the heuristic is wrong about a stray
        /// quote then that value is a legitimate secret — a PEM body, a JSON
        /// blob — and this is a piece of it. Messages about this problem go to
        /// stderr and land in CI logs, which is exactly the reasoning
        /// `EnvelopeError::UnknownRefKind` already applies to the kind it
        /// refuses to echo. [`std::fmt::Display`] therefore names only `key`,
        /// which came from the file's own left-hand side.
        swallowed: String,
    },
    /// A single-line quoted value is followed by more bytes on the same line,
    /// as in `API_KEY='super'password`.
    ///
    /// Unambiguously malformed, and the bytes after the quote are part of no
    /// value: a shell concatenates them, a dotenv reader drops them. The line is
    /// therefore not read as an assignment at all, so the variable is missing
    /// rather than truncated — and a writer must refuse, because rewriting the
    /// quoted half would leave the other half on disk in cleartext.
    TrailingAfterQuote {
        line: usize,
        /// The name the malformed line was trying to assign.
        key: String,
    },
}

impl QuoteProblem {
    /// The 1-based line to point the user at.
    pub fn line(&self) -> usize {
        match self {
            QuoteProblem::Unterminated { line }
            | QuoteProblem::SwallowedAssignment { line, .. }
            | QuoteProblem::TrailingAfterQuote { line, .. } => *line,
        }
    }

    /// Whether a writer must refuse the file rather than warn about it.
    ///
    /// The two unambiguous shapes are fatal; [`QuoteProblem::SwallowedAssignment`]
    /// is a heuristic that a legitimate multi-line value can trip, so it warns.
    /// This is what orders [`Document::quote_problem`]: an advisory must never
    /// stand in for a fatal problem found later in the same file.
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
            // `swallowed` is deliberately not in this message: see its
            // documentation. Only the name the file assigns and the line are.
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
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Finding 6: `API_KEY='super'password` used to read as `super`, with
    /// `password` dropped on the floor. Nothing was lost from the file — the
    /// model is lossless — which is exactly why it was invisible: a round trip
    /// is byte-exact whether or not the value is right.
    ///
    /// Two consequences made it worth refusing rather than guessing. `import`
    /// pushed `super` to the provider and reported success; and `encrypt`
    /// replaced `'super'` with a marker, leaving `password` on disk in
    /// cleartext after it — a value `get` then reports as `super` while a shell
    /// sourcing the file sees `<marker>password`.
    #[test]
    fn a_quoted_value_with_bytes_after_it_is_not_an_assignment() {
        for source in [
            "API_KEY='super'password\n",
            "API_KEY=\"super\"password\n",
            "export API_KEY='super'password\n",
            // Whatever follows, as long as it is not a comment.
            "API_KEY='super' password\n",
            "API_KEY='super'\t'more'\n",
            // Round 3, finding 1a: a *multi-line* quoted value with bytes after
            // its closing quote used to be skipped by the check entirely, so
            // the entry parsed as well formed and `encrypt`, `set` and `import`
            // all rewrote the quoted half and reported success — leaving the
            // tail on disk in cleartext. Every source above is single-line,
            // which is the only case the old gate reached.
            "API_KEY=\"line one\nline two\"password\n",
            "API_KEY='line one\nline two'password\n",
            // And with something after it on the closing quote's own line.
            "API_KEY=\"line one\nline two\" password\n",
        ] {
            let document = Document::parse(source);
            assert_eq!(
                document.get("API_KEY"),
                None,
                "{source:?} was read as an assignment"
            );
            // Still lossless, and still reported.
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

    /// Finding 1a, the consequence: a multi-line value whose tail is outside its
    /// quotes must not be rewritable, because rewriting the quoted half leaves
    /// the tail behind. `Document` is the model's half of it — the entry does
    /// not exist, so `set_value` finds nothing to change.
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

    /// Finding 1b: `quote_problem` returned the *first* problem, so a non-fatal
    /// swallowed assignment earlier in the file hid a fatal trailing-bytes line
    /// later in it — and every writer, which matches on this one value, went
    /// ahead and left that line's cleartext on disk.
    #[test]
    fn a_fatal_quote_problem_is_not_masked_by_an_earlier_advisory() {
        let document =
            Document::parse("CERT=\"line\nINNER=value\nend\"\nAPI_KEY='super'password\n");
        // Both are found...
        let problems = document.quote_problems();
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(matches!(
            problems[0],
            QuoteProblem::SwallowedAssignment { .. }
        ));
        // ...and the one a writer is handed is the fatal one.
        let chosen = document.quote_problem().expect("a problem");
        assert!(chosen.is_fatal(), "{chosen:?}");
        assert!(
            matches!(chosen, QuoteProblem::TrailingAfterQuote { ref key, .. } if key == "API_KEY"),
            "{chosen:?}"
        );
    }

    /// Finding 25: the swallowed name came from *inside* a value, and if the
    /// heuristic is wrong that value is a secret. The message names the file's
    /// own left-hand side and never the fragment.
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

    /// The same rule must not swallow the shapes that are fine: a comment after
    /// a quoted value, trailing whitespace, and a quote that legitimately ends
    /// a multi-line value.
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

    /// Rewriting the file must not resurrect the malformed line as an entry:
    /// setting the same name appends a new assignment, and the broken line is
    /// preserved verbatim. (The provider refuses the write outright — this is
    /// the document model's half of it.)
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
        // Not just the one a shell would use: an assignment left behind is a
        // plaintext secret left behind, in the file this provider exists to
        // make committable.
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

    /// The value is what the caller asked to destroy; the note beside it is
    /// text the user wrote and did not name.
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
        // CRLF, because that is what the file already used.
        assert_eq!(document.to_string(), "# note\r\nB=2\r\n");
    }

    #[test]
    fn an_entry_reports_the_assignments_swallowed_into_its_value() {
        let document = Document::parse("A=\"oops\nB=keepme\nc=fine\"\nD=1\n");
        let entry = document.entry("A").expect("A parses as one entry");
        // Both the one-character and the lowercase name count: each is a
        // variable that `remove` would delete without naming it.
        assert_eq!(entry.enclosed_assignments(), ["B", "c"]);
        // A legitimate multi-line value is not an assignment list. Base64
        // padding makes a line end in `=` behind a valid key name, which is
        // exactly the false positive that would block deleting a PEM key.
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
