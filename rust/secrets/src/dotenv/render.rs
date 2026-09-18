//! Turning a value back into dotenv bytes.
//!
//! The inverse of [`parse`](super::parse): every form produced here must parse
//! back to exactly the value that went in. It must also be inert to a shell,
//! because a `.env` is routinely `source`d — so a bare value is only ever a
//! single safe word, single quotes are preferred (nothing expands inside them),
//! and the double-quoted fallback escapes what quoting alone does not stop.

use super::Quote;

/// Whether `ch` is safe in a value written with no quotes at all.
///
/// An allowlist, not a denylist. A dotenv file is routinely `source`d by a
/// shell and read by interpolating dotenv libraries, so a bare value must be a
/// single word that expands to itself: `$`, backticks, `;`, `&`, `|`, `(`, `)`,
/// `<`, `>`, `*`, `?`, `[`, `]`, `{`, `}`, `!`, `~`, `#`, `\`, whitespace and
/// quotes are all excluded. What is left still covers an encrypted marker
/// (alphanumerics, `-`, `_`, `:`) and an ordinary token or URL.
fn bare_safe(ch: char) -> bool {
    // Unicode alphanumerics stay bare: every shell metacharacter is ASCII, so
    // `Grüße` needs no quoting.
    ch.is_alphanumeric()
        || matches!(
            ch,
            '-' | '_' | '.' | ':' | '/' | '@' | '+' | ',' | '=' | '%'
        )
}

/// Render `value` so that parsing `KEY=<rendered>` yields `value` again,
/// preferring `prefer`'s quoting style when it can represent the value.
///
/// Every form this returns is inert to a shell: bare values are single safe
/// words, single quotes are literal, and [`escape_double`] neutralises what
/// double quotes would otherwise expand.
pub(super) fn render_value(value: &str, prefer: Quote) -> (String, Quote) {
    let bare_ok = !value.is_empty() && value.chars().all(bare_safe);
    // Single quotes are literal in every shell, which makes them the safest
    // wrapper for an arbitrary value; only a single quote itself defeats them.
    let single_ok = !value.contains('\'');

    match prefer {
        Quote::None if bare_ok => (value.to_string(), Quote::None),
        Quote::Single if single_ok => (format!("'{value}'"), Quote::Single),
        Quote::Double => (escape_double(value), Quote::Double),
        // The preferred style cannot represent this value, so pick the safest
        // one that can.
        _ if bare_ok => (value.to_string(), Quote::None),
        _ if single_ok => (format!("'{value}'"), Quote::Single),
        _ => (escape_double(value), Quote::Double),
    }
}

/// Wrap `value` in double quotes, escaping everything the quotes do not stop.
///
/// Double quotes do not make a value literal: a shell still expands `$name`,
/// `${name}`, `$(command)` and `` `command` `` inside them. Without escaping
/// those, quoting a value neither round-trips it nor makes it safe, which left
/// no safe rendering path at all.
fn escape_double(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '$' => out.push_str("\\$"),
            '`' => out.push_str("\\`"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dotenv::Document;

    #[test]
    fn set_value_keeps_the_existing_quote_style() {
        let mut document = Document::parse("A='single'\nB=\"double\"\nC=bare\n");
        document.set_value("A", "new");
        document.set_value("B", "new");
        document.set_value("C", "new");
        assert_eq!(document.to_string(), "A='new'\nB=\"new\"\nC=new\n");
    }

    #[test]
    fn set_value_upgrades_the_quote_style_when_it_must() {
        let mut document = Document::parse("A=bare\nB='single'\n");
        document.set_value("A", " needs quoting ");
        document.set_value("B", "it's quoted");
        // Single quotes are preferred over double: they are literal to a shell,
        // so the value cannot be expanded or split. Only a value containing a
        // single quote falls through to the (now escaped) double-quoted form.
        assert_eq!(
            document.to_string(),
            "A=' needs quoting '\nB=\"it's quoted\"\n"
        );
    }

    #[test]
    fn values_round_trip_through_render_and_parse() {
        let values = [
            "",
            "plain",
            " leading",
            "trailing ",
            "  both  ",
            "a\nb",
            "a\r\nb",
            "with \"double\" quotes",
            "with 'single' quotes",
            "both \" and '",
            "back\\slash",
            "#hash",
            "=equals",
            "tab\there",
            "🔐 unicode",
            "gitguardian:QUJD",
            // Finding 2: shell-active values must round-trip in every form.
            "$HOME",
            "p$aw0rd",
            "${BRACED}",
            "$(touch /tmp/pwned)",
            "`id`",
            "a;b",
            "a|b",
            "a&b",
            "a>b",
            "a b; echo hi",
            "back\\`tick",
            "$'ansi'",
            "50%",
            "can't",
        ];
        for value in values {
            for prefer in [Quote::None, Quote::Single, Quote::Double] {
                let (rendered, _) = render_value(value, prefer);
                let document = Document::parse(&format!("KEY={rendered}\n"));
                assert_eq!(
                    document.get("KEY").as_deref(),
                    Some(value),
                    "value {value:?} rendered as {rendered:?} ({prefer:?}) did not round-trip"
                );
            }
        }
    }

    #[test]
    fn inserted_values_round_trip() {
        let mut document = Document::new();
        let values = ["plain", "  padded  ", "multi\nline", "quote\"and'quote"];
        for (index, value) in values.iter().enumerate() {
            document.insert(&format!("KEY{index}"), value);
        }
        let reparsed = Document::parse(&document.to_string());
        for (index, value) in values.iter().enumerate() {
            assert_eq!(
                reparsed.get(&format!("KEY{index}")).as_deref(),
                Some(*value)
            );
        }
    }

    #[test]
    fn shell_active_values_are_never_written_bare() {
        let dangerous = [
            "$HOME",
            "p$aw0rd",
            "$(touch /tmp/pwned)",
            "`id`",
            "a;b",
            "a|b",
            "a&b",
            "a>b",
            "a<b",
            "a*b",
            "a?b",
            "a(b",
            "a{b",
            "a[b",
            "a!b",
            "~root",
            "a#b-no-wait-that-is-fine",
            "back\\slash",
        ];
        for value in dangerous {
            let (rendered, quote) = render_value(value, Quote::None);
            assert_ne!(
                quote,
                Quote::None,
                "value {value:?} was written bare as {rendered:?}"
            );
        }
    }

    #[test]
    fn the_double_quoted_form_neutralises_expansion() {
        for value in ["$HOME", "$(id)", "`id`", "${X}", "a $B `c`"] {
            let rendered = escape_double(value);
            let body = &rendered[1..rendered.len() - 1];
            for (index, ch) in body.char_indices() {
                if matches!(ch, '$' | '`') {
                    assert!(
                        index > 0 && body.as_bytes()[index - 1] == b'\\',
                        "{ch} is unescaped in {rendered:?}"
                    );
                }
            }
            // And it still round-trips.
            let document = Document::parse(&format!("KEY={rendered}\n"));
            assert_eq!(document.get("KEY").as_deref(), Some(value));
        }
    }

    #[test]
    fn no_rendering_leaves_an_active_metacharacter_unquoted() {
        for value in [
            "$HOME",
            "$(id)",
            "`id`",
            "a;b",
            "a b",
            "can't",
            "both \" and '",
        ] {
            for prefer in [Quote::None, Quote::Single, Quote::Double] {
                let (rendered, quote) = render_value(value, prefer);
                match quote {
                    // Literal to a shell: nothing inside needs escaping.
                    Quote::Single => {
                        assert!(rendered.starts_with('\'') && rendered.ends_with('\''))
                    }
                    Quote::None => assert!(
                        rendered.chars().all(bare_safe),
                        "{rendered:?} is not a safe bare word"
                    ),
                    Quote::Double => {
                        let body = &rendered[1..rendered.len() - 1];
                        for (index, ch) in body.char_indices() {
                            if matches!(ch, '$' | '`') {
                                assert!(
                                    index > 0 && body.as_bytes()[index - 1] == b'\\',
                                    "{ch} unescaped in {rendered:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn a_marker_is_still_written_bare() {
        let marker = "gitguardian:R0dGRQEBYSYTcpVtx9Hn-_bmRfRB2jo6";
        let (rendered, quote) = render_value(marker, Quote::None);
        assert_eq!(quote, Quote::None);
        assert_eq!(rendered, marker);
    }
}
