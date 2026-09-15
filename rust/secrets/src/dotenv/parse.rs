//! Turning dotenv bytes into a [`Document`](super::Document).
//!
//! The parser never fails: anything it does not recognise becomes a
//! [`Line::Other`](super::Line::Other) and is preserved verbatim, which is what
//! makes a parse/serialise round trip byte-exact. Every offset here is a byte
//! index into the original text, so an [`Entry`](super::Entry) can point at the
//! exact span of its own value.
//!
//! [`render`](super::render) is the inverse: whatever this reads, that must be
//! able to write back unchanged.

use std::ops::Range;

use super::{Entry, Line, Quote};

/// Parse the logical line starting at `pos`, returning it and the offset of
/// the next one.
pub(super) fn parse_line(body: &str, pos: usize) -> (Line, usize) {
    let line_end = physical_line_end(body, pos);
    let content_end = trim_terminator(body, pos, line_end);
    let content = &body[pos..content_end];
    let trimmed = content.trim_start();

    if trimmed.is_empty() {
        return (
            Line::Blank(content_with_terminator(body, pos, line_end)),
            line_end,
        );
    }
    if trimmed.starts_with('#') {
        return (
            Line::Comment(content_with_terminator(body, pos, line_end)),
            line_end,
        );
    }

    match parse_entry(body, pos, content_end) {
        Some(Assignment::Entry(entry, next)) => (Line::Entry(entry), next),
        // A malformed quoted assignment is kept verbatim like any other
        // unrecognised line, so the round trip is still byte-exact — but the
        // *whole* construct has to go into the one `Line::Other`, closing quote
        // included. Keeping only its first physical line would leave the tail on
        // the following lines, where the unbalanced opening quote reads as an
        // unterminated one and the real problem — bytes outside the quotes — is
        // never named.
        Some(Assignment::TrailingAfterQuote(_, next)) => {
            (Line::Other(body[pos..next].to_string()), next)
        }
        None => (
            Line::Other(content_with_terminator(body, pos, line_end)),
            line_end,
        ),
    }
}

fn content_with_terminator(body: &str, start: usize, line_end: usize) -> String {
    body[start..line_end].to_string()
}

/// End offset (exclusive) of the physical line starting at `pos`, terminator
/// included.
fn physical_line_end(body: &str, pos: usize) -> usize {
    match body[pos..].find('\n') {
        Some(offset) => pos + offset + 1,
        None => body.len(),
    }
}

/// `line_end` minus the trailing `\n` / `\r\n`.
fn trim_terminator(body: &str, pos: usize, line_end: usize) -> usize {
    let mut end = line_end;
    if body[pos..end].ends_with('\n') {
        end -= 1;
        if body[pos..end].ends_with('\r') {
            end -= 1;
        }
    }
    end
}

/// What [`parse_entry`] made of a line that has a `KEY=` on it.
enum Assignment {
    /// A well-formed entry, with the offset of the next logical line.
    Entry(Entry, usize),
    /// A quoted value with more bytes after its closing quote, as in
    /// `API_KEY='super'password`. Malformed rather than readable: see
    /// [`trailing_bytes_after_quote`]. Carries the name it tried to assign and
    /// the offset just past the line the closing quote is on — the value may be
    /// multi-line, so that is not necessarily the line the `KEY=` is on.
    TrailingAfterQuote(String, usize),
}

/// Try to read a `KEY=value` assignment starting at `pos`.
///
/// A quoted value may run past `content_end` onto following lines; the
/// returned offset is the start of the next logical line.
fn parse_entry(body: &str, pos: usize, content_end: usize) -> Option<Assignment> {
    let content = &body[pos..content_end];
    let mut cursor = pos + (content.len() - content.trim_start().len());

    // An optional `export ` prefix, as written by `export KEY=value`.
    if let Some(rest) = body[cursor..content_end].strip_prefix("export")
        && rest.starts_with([' ', '\t'])
    {
        cursor += "export".len();
        cursor += rest.len() - rest.trim_start_matches([' ', '\t']).len();
    }

    let equals = cursor + body[cursor..content_end].find('=')?;
    let key = body[cursor..equals].trim_end();
    if !is_valid_key(key) {
        return None;
    }

    let after_equals = equals + 1;
    let value_start = after_equals + count_leading(&body[after_equals..content_end], [' ', '\t']);

    let (quote, value_span) = match body[value_start..].chars().next() {
        // A quoted value may contain newlines, so scan the rest of the file,
        // not just this line.
        Some('"') => (
            Quote::Double,
            value_start..closing_quote(body, value_start, '"', true)?,
        ),
        Some('\'') => (
            Quote::Single,
            value_start..closing_quote(body, value_start, '\'', false)?,
        ),
        // Unquoted: to the end of the line or the start of an inline comment,
        // trailing whitespace excluded (it stays in `raw`, outside the value
        // span).
        _ => (
            Quote::None,
            unquoted_value_span(body, after_equals, value_start, content_end),
        ),
    };

    let line_end = physical_line_end(body, value_span.end);
    // Checked for a multi-line value too. The closing quote of
    // `PRIVATE_KEY="line one\nline two"TAIL` is on the value's *last* physical
    // line, and `TAIL` after it is outside every value just as surely as in the
    // single-line case — but a `!contains('\n')` guard here skipped the check,
    // so the entry parsed as well formed and `encrypt`, `set` and `import` all
    // rewrote the quoted half and left the tail on disk in cleartext.
    if quote != Quote::None && has_trailing_bytes(body, value_span.end, line_end) {
        return Some(Assignment::TrailingAfterQuote(key.to_string(), line_end));
    }
    Some(Assignment::Entry(
        Entry {
            key: key.to_string(),
            raw: body[pos..line_end].to_string(),
            value_span: (value_span.start - pos)..(value_span.end - pos),
            quote,
        },
        line_end,
    ))
}

/// Whether anything but whitespace and a comment follows a closing quote at
/// `end` on the same physical line.
///
/// `KEY='v' # note` and `KEY='v'` are fine; `KEY='super'password` is not. The
/// bytes after the quote belong to no value and to no comment, so every reader
/// has to invent a rule for them: a shell concatenates (`superpassword`), this
/// parser used to keep only `super` and drop the rest silently. Dropping them is
/// the dangerous answer — `encrypt` would replace `'super'` with a marker and
/// leave `password` on disk in cleartext, and `import` would push a value that
/// is not what the file says. So the whole assignment is refused instead.
fn has_trailing_bytes(body: &str, end: usize, line_end: usize) -> bool {
    let rest = &body[end..trim_terminator(body, end, line_end)];
    let trimmed = rest.trim_start_matches([' ', '\t']);
    !trimmed.is_empty() && !trimmed.starts_with('#')
}

/// The variable name of an assignment whose quoted value is followed by bytes
/// that belong to neither the value nor a comment.
///
/// Such a line is parsed as [`Line::Other`], so the only way to report it is to
/// look at the raw line again. Only reached for lines the parser already
/// refused, which is why it can afford to redo the work.
pub(super) fn trailing_bytes_after_quote(raw: &str) -> Option<String> {
    let content_end = trim_terminator(raw, 0, raw.len());
    match parse_entry(raw, 0, content_end)? {
        Assignment::TrailingAfterQuote(key, _) => Some(key),
        Assignment::Entry(..) => None,
    }
}

/// Offset just past the quote closing the one at `open`, or `None` if the
/// value is unterminated.
fn closing_quote(body: &str, open: usize, quote: char, escapes: bool) -> Option<usize> {
    let mut chars = body[open + quote.len_utf8()..].char_indices();
    while let Some((offset, ch)) = chars.next() {
        if escapes && ch == '\\' {
            // Skip whatever the backslash escapes, including a quote.
            chars.next();
            continue;
        }
        if ch == quote {
            return Some(open + quote.len_utf8() + offset + quote.len_utf8());
        }
    }
    None
}

/// Byte range of an unquoted value: from the first byte of the value to where
/// an inline comment starts, if any, with trailing whitespace trimmed.
///
/// `API_KEY=old # rotated monthly` is a value of `old` followed by a comment,
/// not a value with a `#` in it. Getting this wrong is not just a fidelity bug:
/// the comment ends up inside the value span, so rewriting the value deletes
/// the user's comment — and an encrypted marker followed by a comment fails to
/// base64-decode, making the secret unreadable.
///
/// A `#` only opens a comment when whitespace separates it from the value, so
/// `KEY=#tag` is still the value `#tag`, matching what dotenv readers do.
///
/// # Why an empty value anchors at the `=`
///
/// An empty value has nowhere obvious to sit, and the choice matters as soon as
/// something is written into it. In `API_KEY= # from the dashboard` the only
/// candidate positions are just after the `=` and at the `#`, and anchoring at
/// the `#` glues a replacement to the comment: `set` would produce
/// `API_KEY= abc# from the dashboard`, which reads back as a *different* value,
/// and for an encrypted marker reads back as no value at all — the base64 no
/// longer decodes, so the secret `set` reported storing is unrecoverable.
/// Anchoring after the `=` keeps the separating whitespace and the comment
/// where the user put them: `API_KEY=abc # from the dashboard`.
fn unquoted_value_span(
    body: &str,
    after_equals: usize,
    value_start: usize,
    content_end: usize,
) -> Range<usize> {
    let text = &body[value_start..content_end];
    let mut end = text.len();
    if value_start > after_equals && text.starts_with('#') {
        // `KEY= # note`: the whitespace we skipped is the separator, so the
        // value is empty.
        end = 0;
    } else {
        let bytes = text.as_bytes();
        for index in 1..bytes.len() {
            if bytes[index] == b'#' && matches!(bytes[index - 1], b' ' | b'\t') {
                end = index;
                break;
            }
        }
    }
    end -= count_trailing(&text[..end], [' ', '\t']);
    if end == 0 {
        // Empty, so the span is a caret rather than a range: put it against the
        // `=`, ahead of any whitespace and comment. See above.
        return after_equals..after_equals;
    }
    value_start..value_start + end
}

fn count_leading(text: &str, chars: [char; 2]) -> usize {
    text.len() - text.trim_start_matches(chars).len()
}

fn count_trailing(text: &str, chars: [char; 2]) -> usize {
    text.len() - text.trim_end_matches(chars).len()
}

/// Longest name this will believe is a swallowed variable. Env var names are
/// short; a base64 line is not.
const MAX_SWALLOWED_NAME: usize = 64;

/// The first assignment found on a continuation line of a multi-line value.
///
/// Only lines *after* the first count: the value's own first line is by
/// definition not a swallowed assignment. Deliberately conservative, because it
/// can only ever produce a warning and a false positive is pure noise:
///
/// - the name must start the line, so indented content (JSON, YAML) is out;
/// - it must be upper case, which is the dotenv convention and rules out the
///   lower-case runs that base64 is full of;
/// - the `=` must be followed by an actual value, and the name must be short.
///   Base64 padding is exactly `NAME=` or `NAME==` with nothing after it, so
///   requiring a value is what separates the two; there is no way to tell a
///   padded base64 line from an empty assignment, so this stays quiet.
///
/// The cost is that a swallowed *lower-case* variable, or one with an empty
/// value, goes unreported. That is the right way round: this warns, it never
/// blocks, and a false positive on every PEM key in a file would be worse than
/// silence.
pub(super) fn swallowed_assignment(value: &str) -> Option<String> {
    let mut lines = value.split('\n');
    lines.next()?;
    for line in lines {
        let line = line.trim_end_matches('\r');
        let candidate = line.strip_prefix("export ").unwrap_or(line);
        let Some((name, rest)) = candidate.split_once('=') else {
            continue;
        };
        if is_valid_key(name)
            && (2..=MAX_SWALLOWED_NAME).contains(&name.len())
            && !name.chars().any(|ch| ch.is_ascii_lowercase())
            && name.chars().any(|ch| ch.is_ascii_uppercase())
            && !rest.starts_with('=')
            && !rest.trim().is_empty()
        {
            return Some(name.to_string());
        }
    }
    None
}

/// Every assignment that appears *inside* a multi-line value.
///
/// The deletion counterpart to [`swallowed_assignment`], and deliberately
/// broader than it. That one decides whether to *warn* about a file, so it is
/// tuned against false positives: it wants an all-uppercase name of at least
/// two characters, and stays quiet otherwise. This one decides whether
/// removing an entry would destroy a variable nobody named — the lines it
/// misses are lines that get deleted with no warning at all — so the balance
/// flips, and `B=keepme` (one character) or `b=keepme` (lowercase) has to
/// count.
///
/// What it still refuses to call an assignment is base64, because a PEM or a
/// certificate is the multi-line value this format exists to carry and
/// deleting one must keep working: padding makes `MIIEvQ...abc=` end in `=`
/// with a perfectly valid key name in front of it, so an empty right-hand side
/// is not an assignment, and neither is one starting with `=`.
pub(super) fn enclosed_assignments(value: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut lines = value.split('\n');
    // The first line is the one the `KEY=` itself is on.
    lines.next();
    for line in lines {
        let line = line.trim_end_matches('\r');
        let candidate = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((name, rest)) = candidate.split_once('=') else {
            continue;
        };
        if is_valid_key(name) && !rest.starts_with('=') && !rest.trim().is_empty() {
            found.push(name);
        }
    }
    found
}

/// Whether `raw` ends inside a quote that it opened.
///
/// Deliberately errs towards saying yes: a false positive costs the user a
/// clear error naming the line, a false negative costs them two variables.
pub(super) fn opens_unterminated_quote(raw: &str) -> bool {
    let mut open: Option<char> = None;
    let mut escaped = false;
    for ch in raw.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match (open, ch) {
            // Single quotes are literal: only another single quote ends them,
            // and a backslash inside them escapes nothing.
            (Some('\''), '\'') => open = None,
            (Some('\''), _) => {}
            (Some('"'), '\\') => escaped = true,
            (Some('"'), '"') => open = None,
            (Some(_), _) => {}
            (None, '\\') => escaped = true,
            (None, quote @ ('"' | '\'')) => open = Some(quote),
            (None, _) => {}
        }
    }
    open.is_some()
}

/// Whether `key` is a usable environment variable name.
pub fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// Expand the escapes a double-quoted value may contain.
pub(super) fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            // Escaped by `escape_double` so a double-quoted value cannot be
            // expanded by a shell; undone here so the round trip is exact.
            Some('$') => out.push('$'),
            Some('`') => out.push('`'),
            // Not an escape we define: keep both bytes, so re-rendering is
            // still faithful.
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dotenv::{Document, QuoteProblem};

    const UGLY_FIXTURES: &[(&str, &str)] = &[
        ("empty", ""),
        ("only a newline", "\n"),
        ("no trailing newline", "A=1\nB=2"),
        ("crlf", "A=1\r\nB=2\r\n"),
        ("crlf without final newline", "A=1\r\nB=2"),
        ("mixed endings", "A=1\r\nB=2\nC=3"),
        ("bom", "\u{feff}A=1\n"),
        ("bom and crlf", "\u{feff}# comment\r\nA=1\r\n"),
        ("export prefix", "export A=1\nexport\tB=2\n"),
        ("quotes", "A=plain\nB=\"double\"\nC='single'\n"),
        (
            "multi-line double quoted",
            "KEY=\"line one\nline two\nline three\"\nAFTER=1\n",
        ),
        (
            "multi-line single quoted with crlf",
            "KEY='line one\r\nline two'\r\nAFTER=1\r\n",
        ),
        ("escaped quote inside value", "A=\"a \\\" b\"\nB=2\n"),
        ("duplicate keys", "A=1\nA=2\nA=3\n"),
        (
            "comments containing equals",
            "# OLD=disabled\n#see https://example.com/x?a=b\nA=1\n",
        ),
        ("non-ascii", "GRÜSSE=Grüße\nEMOJI=\"🔐 ok\"\n"),
        ("trailing whitespace", "A=1   \nB=2\t\n   \nC=3\n"),
        ("blank line runs", "\n\n\nA=1\n\n\n\nB=2\n\n"),
        ("spaces around equals", "A = 1\nB=  spaced  \n"),
        ("value with hash", "A=#not-a-comment\nB=a#b\n"),
        ("indented entries", "    A=1\n\tB=2\n"),
        ("empty values", "A=\nB=\"\"\nC=''\n"),
        ("malformed lines", "not an assignment\n1BAD=x\nA=1\n"),
        ("unterminated quote", "A=\"open\nB=2\n"),
        ("equals inside value", "A=k=v\nB==leading\n"),
        (
            "marker values",
            "SECRET=gitguardian:AAAABBBBCCCC\nPLAIN=hello\n",
        ),
    ];

    #[test]
    fn ugly_fixtures_round_trip_byte_for_byte() {
        for (name, source) in UGLY_FIXTURES {
            let document = Document::parse(source);
            assert_eq!(
                document.to_string(),
                *source,
                "fixture '{name}' did not round-trip"
            );
        }
    }

    #[test]
    fn parses_keys_and_values() {
        let document = Document::parse(
            "export A=plain\nB=\"double \\\"quoted\\\"\"\nC='single'\nD=  spaced  \nE=\n",
        );
        assert_eq!(document.get("A").as_deref(), Some("plain"));
        assert_eq!(document.get("B").as_deref(), Some("double \"quoted\""));
        assert_eq!(document.get("C").as_deref(), Some("single"));
        assert_eq!(document.get("D").as_deref(), Some("spaced"));
        assert_eq!(document.get("E").as_deref(), Some(""));
        assert_eq!(document.get("MISSING"), None);
    }

    #[test]
    fn multi_line_quoted_values_are_one_entry() {
        let document = Document::parse("KEY=\"one\ntwo\"\nAFTER=1\n");
        assert_eq!(document.entries().count(), 2);
        assert_eq!(document.get("KEY").as_deref(), Some("one\ntwo"));
        assert_eq!(document.get("AFTER").as_deref(), Some("1"));
    }

    #[test]
    fn escapes_round_trip_through_a_value() {
        let document = Document::parse("A=\"tab\\there\\nnewline\\\\slash\"\n");
        assert_eq!(
            document.get("A").as_deref(),
            Some("tab\there\nnewline\\slash")
        );
    }

    #[test]
    fn an_inline_comment_is_not_part_of_the_value() {
        let document = Document::parse("API_KEY=old # rotated monthly\n");
        assert_eq!(document.get("API_KEY").as_deref(), Some("old"));
    }

    #[test]
    fn a_marker_followed_by_a_comment_parses_as_the_marker() {
        let document = Document::parse("SECRET=gitguardian:QUJDREVGRw # device-local\n");
        assert_eq!(
            document.get("SECRET").as_deref(),
            Some("gitguardian:QUJDREVGRw")
        );
    }

    #[test]
    fn a_hash_that_is_not_a_comment_stays_in_the_value() {
        // No whitespace separator, so it is part of the value.
        let document = Document::parse("A=#not-a-comment\nB=a#b\nC=a #comment\nD= #comment\n");
        assert_eq!(document.get("A").as_deref(), Some("#not-a-comment"));
        assert_eq!(document.get("B").as_deref(), Some("a#b"));
        assert_eq!(document.get("C").as_deref(), Some("a"));
        assert_eq!(document.get("D").as_deref(), Some(""));
    }

    #[test]
    fn a_quoted_value_keeps_a_hash_and_can_be_followed_by_a_comment() {
        let document = Document::parse("A=\"has # inside\"\n");
        assert_eq!(document.get("A").as_deref(), Some("has # inside"));
    }

    #[test]
    fn an_unterminated_quote_is_reported_with_its_line_number() {
        let document = Document::parse("A=1\nNOTE=\"oops\nAPI_KEY=abc\n");
        assert_eq!(
            document.quote_problem(),
            Some(QuoteProblem::Unterminated { line: 2 })
        );

        let document = Document::parse("NOTE='oops\nA=1\n");
        assert_eq!(
            document.quote_problem(),
            Some(QuoteProblem::Unterminated { line: 1 })
        );
    }

    #[test]
    fn a_quote_that_pairs_with_a_later_one_is_still_reported() {
        // The closing quote is the one on the last line and nothing follows it,
        // so the file is *balanced* — a quote count says it is fine — while two
        // variables have already collapsed into one value.
        let document = Document::parse("NOTE=\"oops\nAPI_KEY=abc\nOTHER=\"\n");
        // Proof the damage is real: one entry, not three.
        assert_eq!(document.entries().count(), 1);
        assert_eq!(document.get("API_KEY"), None);
        assert_eq!(
            document.quote_problem(),
            Some(QuoteProblem::SwallowedAssignment {
                line: 1,
                key: "NOTE".to_string(),
                swallowed: "API_KEY".to_string(),
            })
        );
        let rendered = document.quote_problem().unwrap().to_string();
        // Finding 25: the name it found *inside* the value is a fragment of that
        // value, so the message names only the entry the file assigns.
        assert!(!rendered.contains("API_KEY"), "{rendered}");
        assert!(rendered.contains("'NOTE'"), "{rendered}");
        assert!(rendered.contains("line 1"), "{rendered}");
    }

    /// Finding 1a, the other half of the same shape: when the stray quote pairs
    /// with a *legitimate* opening quote further down, the bytes after that pair
    /// closes are outside every value — `END="fine` leaves `fine` there. That is
    /// the trailing-bytes hazard, not an advisory, and it is now fatal: sealing
    /// the quoted half would leave `fine` on disk.
    #[test]
    fn a_pair_that_strands_bytes_after_it_is_fatal_not_advisory() {
        let document = Document::parse("NOTE=\"oops\nAPI_KEY=abc\nEND=\"fine\n");
        assert_eq!(document.entries().count(), 0);
        let problem = document.quote_problem().expect("a problem");
        assert!(problem.is_fatal(), "{problem:?}");
        assert!(
            matches!(problem, QuoteProblem::TrailingAfterQuote { line: 1, ref key } if key == "NOTE"),
            "{problem:?}"
        );
        // Still lossless.
        assert_eq!(
            document.to_string(),
            "NOTE=\"oops\nAPI_KEY=abc\nEND=\"fine\n"
        );
    }

    #[test]
    fn a_legitimate_multiline_value_is_not_reported() {
        for source in [
            // a PEM key: base64 padding must not read as an assignment
            "KEY=\"-----BEGIN X-----\nabc/def+ghi\njkl==\n-----END X-----\"\nAFTER=1\n",
            // upper-case base64 with single padding, the nastiest lookalike
            "KEY=\"-----BEGIN X-----\nMIIBCGKCAQEAXYZ=\n-----END X-----\"\nAFTER=1\n",
            // a lower-case name is not believed, by design
            "KEY=\"line one\nfoo=bar\"\n",
            // nor an empty assignment: indistinguishable from base64 padding
            "KEY=\"line one\nEMPTY=\"\n",
            // indented content, so no line starts with an identifier
            "JSON='{\n  \"a\": 1,\n  \"b\": 2\n}'\n",
            // a single-line value that happens to contain an assignment
            "CMD='FOO=bar make all'\n",
            "URL=https://x/y?a=b\n",
        ] {
            assert_eq!(
                Document::parse(source).quote_problem(),
                None,
                "false positive on {source:?}"
            );
        }
    }

    #[test]
    fn a_multiline_value_containing_an_assignment_is_a_known_false_positive() {
        let document = Document::parse("SCRIPT=\"cd /app\nFOO=bar\n\"\n");
        assert!(matches!(
            document.quote_problem(),
            Some(QuoteProblem::SwallowedAssignment { .. })
        ));
    }

    #[test]
    fn a_well_formed_document_has_no_unterminated_quote() {
        for (name, source) in UGLY_FIXTURES {
            let flagged = Document::parse(source).quote_problem();
            let expected = source.contains("A=\"open");
            assert_eq!(
                flagged.is_some(),
                expected,
                "fixture '{name}' was {flagged:?}"
            );
        }
        assert_eq!(
            Document::parse("KEY=\"line one\nline two\"\nAFTER=1\n").quote_problem(),
            None
        );
        assert_eq!(
            Document::parse("# a comment with a \" in it\nA=1\n").quote_problem(),
            None
        );
        assert_eq!(
            Document::parse("A=\"escaped \\\" quote\"\nB=2\n").quote_problem(),
            None
        );
    }

    #[test]
    fn malformed_lines_are_preserved_but_not_entries() {
        let document = Document::parse("not an assignment\n1BAD=x\nGOOD=1\n");
        assert_eq!(document.entries().count(), 1);
        assert_eq!(document.get("GOOD").as_deref(), Some("1"));
        assert!(matches!(document.lines()[0], Line::Other(_)));
        assert!(matches!(document.lines()[1], Line::Other(_)));
    }

    /// The one fragment that is ambiguous by construction: it opens a quote
    /// nothing on its own line closes, so it pairs with whatever quote comes
    /// next and swallows the lines in between. The round trip still has to be
    /// byte-exact for a file containing it — that is the point of the corpus —
    /// but the *edit* assertions cannot be: rewriting the swallowing value can
    /// leave the tail of a later line stranded outside the new quotes, which
    /// reparses as a malformed assignment rather than as the value just
    /// written. Writing to such a file is refused (`set_secrets`,
    /// `encrypt_in_place`) precisely because its meaning is already lost.
    const DANGLING_QUOTE: &str = "H=\"unterminated";

    #[test]
    fn generated_documents_round_trip() {
        const FRAGMENTS: &[&str] = &[
            "A=1",
            "export B=two",
            "  C = three  ",
            "D=\"double \\\" quoted\"",
            "E='single'",
            "F=\"multi\nline\"",
            "G='multi\nline'",
            "# comment with = inside",
            "#",
            "",
            "   ",
            "not an assignment",
            "1BAD=x",
            DANGLING_QUOTE,
            "I=gitguardian:QUJDRA",
            "J=Grüße 🔐",
            "A=1",
            "K=",
            "L=\"\"",
        ];
        // A tiny LCG keeps the corpus deterministic without a dependency.
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = move || {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) as usize
        };
        let mut edited_cases_skipped = 0;
        for case in 0..500 {
            let mut source = String::new();
            if case % 7 == 0 {
                source.push('\u{feff}');
            }
            let newline = if case % 3 == 0 { "\r\n" } else { "\n" };
            let count = next() % 12;
            for _ in 0..count {
                source.push_str(FRAGMENTS[next() % FRAGMENTS.len()]);
                source.push_str(newline);
            }
            // Half the files end without a final newline.
            if case % 2 == 0 && source.ends_with(newline) {
                source.truncate(source.len() - newline.len());
            }
            let document = Document::parse(&source);
            assert_eq!(
                document.to_string(),
                source,
                "case {case} did not round-trip"
            );

            // Rewriting a value must keep every other byte identical.
            //
            // Only for a document whose quoting is unambiguous: see
            // [`DANGLING_QUOTE`]. The heuristic in `quote_problem` catches most
            // of those, and the fragment itself catches the rest — it cannot
            // report a swallowed single-letter name or an empty assignment, by
            // design.
            if document.quote_problem().is_some() || source.contains(DANGLING_QUOTE) {
                edited_cases_skipped += 1;
                continue;
            }
            if let Some(key) = document
                .entries()
                .next_back()
                .map(|entry| entry.key().to_string())
            {
                let mut edited = Document::parse(&source);
                assert!(edited.set_value(&key, "replacement") > 0);
                assert_eq!(edited.get(&key).as_deref(), Some("replacement"));
                let reparsed = Document::parse(&edited.to_string());
                assert_eq!(reparsed.to_string(), edited.to_string());
                assert_eq!(
                    reparsed.get(&key).as_deref(),
                    Some("replacement"),
                    "case {case}"
                );
                assert_eq!(reparsed.entries().count(), document.entries().count());
            }
        }
        // The edit half must still be exercised by most of the corpus, or the
        // guard above would have quietly turned it off.
        assert!(edited_cases_skipped < 250, "{edited_cases_skipped}");
    }
}
