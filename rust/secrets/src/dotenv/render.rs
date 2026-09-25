//! Value rendering, the inverse of [`parse`](super::parse). Output must also be
//! inert to a shell, because a `.env` is routinely `source`d.

use super::Quote;

/// An allowlist, not a denylist: a bare value must be a shell word that expands to itself.
fn bare_safe(ch: char) -> bool {
    // Every shell metacharacter is ASCII, so Unicode alphanumerics stay bare.
    ch.is_alphanumeric()
        || matches!(
            ch,
            '-' | '_' | '.' | ':' | '/' | '@' | '+' | ',' | '=' | '%'
        )
}

/// zsh expands `=cmd` to the command's path at the start of an assignment's
/// value and after each `:`, and aborts the `source` when there is no such command.
fn zsh_equals_expands(value: &str) -> bool {
    value.starts_with('=') || value.contains(":=")
}

/// Prefers `prefer`'s quoting style when it can represent the value.
pub(super) fn render_value(value: &str, prefer: Quote) -> (String, Quote) {
    let bare_ok = !value.is_empty() && value.chars().all(bare_safe) && !zsh_equals_expands(value);
    let single_ok = !value.contains('\'');

    match prefer {
        Quote::None if bare_ok => (value.to_string(), Quote::None),
        Quote::Single if single_ok => (format!("'{value}'"), Quote::Single),
        Quote::Double => (escape_double(value), Quote::Double),
        _ if bare_ok => (value.to_string(), Quote::None),
        _ if single_ok => (format!("'{value}'"), Quote::Single),
        _ => (escape_double(value), Quote::Double),
    }
}

/// A shell still expands `$` and backticks inside double quotes, so escape them.
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
// A failed unwrap in a test is the assertion failing.
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
    fn a_value_zsh_would_expand_as_a_command_path_is_quoted() {
        for value in ["=ls", "==ls", "=nope", "a:=ls", "x:y:=z"] {
            let (rendered, quote) = render_value(value, Quote::None);
            assert_ne!(
                quote,
                Quote::None,
                "{value:?} was written bare as {rendered:?}"
            );
        }
        for value in ["a=b", "abc==", "k=v,x=y"] {
            assert_eq!(render_value(value, Quote::None).1, Quote::None, "{value:?}");
        }
    }

    /// Sourced for real: every rendering must read back unchanged in each shell.
    #[cfg(unix)]
    #[test]
    fn rendered_values_are_inert_when_sourced_by_a_shell() {
        let values = [
            "=ls", "==nope", "a:=ls", "~root", "a:~root", "$HOME", "`id`", "it's", "50%", "a=b",
            "-=x",
        ];
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("rendered.env");
        let mut contents = String::new();
        for (index, value) in values.iter().enumerate() {
            let (rendered, _) = render_value(value, Quote::None);
            contents.push_str(&format!("V{index}={rendered}\n"));
        }
        std::fs::write(&file, contents).unwrap();
        let probe: String = (0..values.len())
            .map(|index| format!("printf '%s\\n' \"$V{index}\"; "))
            .collect();
        for (shell, flags) in [
            ("sh", &[][..]),
            ("bash", &["--norc"][..]),
            ("zsh", &["-f"][..]),
        ] {
            let Ok(output) = std::process::Command::new(shell)
                .args(flags)
                .arg("-c")
                .arg(format!(". '{}' && {probe}", file.display()))
                .output()
            else {
                assert!(
                    std::env::var_os("GITGUARDIAN_REQUIRE_SHELLS").is_none(),
                    "{shell} is not installed"
                );
                continue;
            };
            let expected: String = values.iter().map(|value| format!("{value}\n")).collect();
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                expected,
                "{shell}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
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
