use std::collections::BTreeMap;

use anyhow::{Result, bail, ensure};
use ggshield_secrets::dotenv::{Document, Line, QuoteProblem};
use secrecy::{ExposeSecret, SecretString};

/// Read dotenv `KEY=value` entries for `import`.
///
/// Parsing is [`Document`]'s, the same model the file provider uses, so a
/// multi-line quoted value — a PEM key being the usual one — is one entry here
/// too. What stays local is the *import policy*, which is stricter than reading
/// a dotenv file for its values: a line that is not an assignment is an error
/// rather than something to preserve, because the caller handed us a file
/// expecting all of it to be imported.
pub(crate) fn parse_dotenv(contents: &str) -> Result<BTreeMap<String, SecretString>> {
    let document = Document::parse(contents);
    match document.quote_problem() {
        // The values after a stray quote are swallowed into one, so importing
        // would push a value nobody wrote.
        Some(problem @ QuoteProblem::Unterminated { .. }) => bail!(
            "{problem}; fix it before importing, or the variables after it are swallowed into \
             one value"
        ),
        // Part of the value is outside its quotes, so whatever we imported
        // would not be what the file says — and the other part would stay
        // behind in cleartext.
        Some(problem @ QuoteProblem::TrailingAfterQuote { .. }) => bail!(
            "{problem}; fix it before importing, or the value pushed to the provider is not the \
             one in the file"
        ),
        Some(problem @ QuoteProblem::SwallowedAssignment { .. }) => {
            eprintln!("warning: {problem}");
        }
        None => {}
    }

    let mut fields = BTreeMap::new();
    let mut line_number = 1;
    for line in document.lines() {
        match line {
            Line::Blank(_) => {}
            Line::Comment(raw) => {
                // Comments are never fatal: only warn when one parses as a real
                // assignment (a likely disabled env var). Prose that happens to
                // contain '=' — a URL with query parameters, say — is just a
                // comment.
                if let Some(key) = commented_env_var(raw) {
                    eprintln!("warning: ignored commented env var '{key}' on line {line_number}");
                }
            }
            Line::Entry(entry) => {
                let value = SecretString::from(entry.value());
                // Same rule as `set`: a value nothing can ever inject must not
                // be pushed to a provider and reported as imported.
                validate_env_value(entry.key(), &value)?;
                if fields.insert(entry.key().to_string(), value).is_some() {
                    eprintln!(
                        "warning: duplicate env var '{}' on line {line_number}; keeping later value",
                        entry.key()
                    );
                }
            }
            Line::Other(raw) => return Err(not_an_assignment(raw, line_number)),
        }
        // A quoted value may span several physical lines.
        line_number += line.raw().matches('\n').count().max(1);
    }
    ensure!(!fields.is_empty(), "no env vars found");
    Ok(fields)
}

/// The variable name a commented-out assignment would have defined.
fn commented_env_var(raw: &str) -> Option<String> {
    let body = raw.trim().trim_start_matches('#').trim();
    let (key, _) = parse_env_assignment(body).ok().flatten()?;
    Some(key)
}

/// Explain a line the parser could not read as an assignment.
///
/// An invalid *name* is the common cause and worth saying so precisely; only
/// fall back to the generic message when there is no assignment there at all.
fn not_an_assignment(raw: &str, line_number: usize) -> anyhow::Error {
    let content = raw.trim();
    let candidate = content
        .strip_prefix("export ")
        .unwrap_or(content)
        .trim_start();
    if let Some((key, _)) = candidate.split_once('=')
        && let Err(error) = validate_env_key(key.trim())
    {
        // Flattened rather than layered: the caller prints this with `{}` and
        // the name is the part they need to see.
        return anyhow::anyhow!("line {line_number}: {error}");
    }
    anyhow::anyhow!("line {line_number} is not a KEY=value assignment")
}

fn parse_env_assignment(line: &str) -> Result<Option<(String, String)>> {
    let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
    let Some((key, value)) = line.split_once('=') else {
        return Ok(None);
    };
    let key = key.trim();
    validate_env_key(key)?;
    Ok(Some((key.to_string(), unquote_env_value(value.trim()))))
}

fn unquote_env_value(value: &str) -> String {
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

/// Refuse a value that cannot be handed to a child process.
///
/// A NUL is a valid UTF-8 code point, so it survives being read out of a dotenv
/// file, and `Command::env` then rejects it — as a spawn failure whose message
/// ("nul byte found in provided data") names neither the variable nor the file.
/// Caught here so it names both, and so one bad entry is reported as one bad
/// entry rather than as "running printenv failed".
///
/// Names the field and never the value.
pub(crate) fn validate_env_value(key: &str, value: &SecretString) -> Result<()> {
    ensure!(
        !value.expose_secret().contains('\0'),
        "the value of '{key}' contains a NUL byte, which cannot be passed to a child process; \
         fix that value at its source"
    );
    Ok(())
}

pub(crate) fn validate_env_key(key: &str) -> Result<()> {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        bail!("env var name cannot be empty");
    };
    ensure!(
        first == '_' || first.is_ascii_alphabetic(),
        "'{key}' is not a valid env var name"
    );
    ensure!(
        chars.all(|c| c == '_' || c.is_ascii_alphanumeric()),
        "'{key}' is not a valid env var name"
    );
    Ok(())
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn parse_dotenv_reads_assignments_and_warns_comments() {
        let env = parse_dotenv(
            r#"
            # OLD_KEY=ignored
            KEY=value
            export QUOTED="quoted value"
            EMPTY=
            "#,
        )
        .unwrap();

        assert_eq!(env.get("KEY").unwrap().expose_secret(), "value");
        assert_eq!(env.get("QUOTED").unwrap().expose_secret(), "quoted value");
        assert_eq!(env.get("EMPTY").unwrap().expose_secret(), "");
        assert!(!env.contains_key("OLD_KEY"));
    }

    #[test]
    fn parse_dotenv_ignores_comments_that_do_not_parse_as_assignments() {
        let env = parse_dotenv(
            r#"
            # see https://example.com/page?a=b for details
            KEY=value
            "#,
        )
        .unwrap();
        assert_eq!(env.len(), 1);
        assert_eq!(env.get("KEY").unwrap().expose_secret(), "value");
    }

    /// The reason this shares the file provider's parser: a value spanning
    /// several lines is one entry, not a parse error. The old line-based reader
    /// rejected a PEM key outright.
    #[test]
    fn parse_dotenv_reads_a_multiline_quoted_value() {
        let env = parse_dotenv(
            "PRIVATE_KEY=\"-----BEGIN KEY-----\nfake-line-two\n-----END KEY-----\"\nAFTER=1\n",
        )
        .unwrap();
        assert_eq!(env.len(), 2);
        assert_eq!(
            env.get("PRIVATE_KEY").unwrap().expose_secret(),
            "-----BEGIN KEY-----\nfake-line-two\n-----END KEY-----"
        );
        assert_eq!(env.get("AFTER").unwrap().expose_secret(), "1");
    }

    /// Escapes and quoting styles resolve the same way they do when the file
    /// provider reads them, rather than by stripping outer quotes.
    #[test]
    fn parse_dotenv_resolves_quoting_like_the_provider_does() {
        let env = parse_dotenv("A='single'\nB=\"tab\\there\"\nC=bare\nD=\"do$llar\"\n").unwrap();
        assert_eq!(env.get("A").unwrap().expose_secret(), "single");
        assert_eq!(env.get("B").unwrap().expose_secret(), "tab\there");
        assert_eq!(env.get("C").unwrap().expose_secret(), "bare");
        assert_eq!(env.get("D").unwrap().expose_secret(), "do$llar");
    }

    /// A stray quote swallows the variables after it, so importing such a file
    /// would push a value nobody wrote.
    #[test]
    fn parse_dotenv_refuses_an_unterminated_quote() {
        let error = parse_dotenv("NOTE=\"oops\nKEY=value\n").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("never closed"), "{message}");
        assert!(message.contains("swallowed"), "{message}");
    }

    /// Finding 6a: `API_KEY='super'password` used to import as `super` and
    /// report success, pushing a value to the provider that is not the one in
    /// the file — and leaving the rest of it behind.
    #[test]
    fn parse_dotenv_refuses_a_value_that_is_partly_outside_its_quotes() {
        let error = parse_dotenv("API_KEY='super'password\nOTHER=fine\n").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("API_KEY"), "{message}");
        assert!(message.contains("closing quote"), "{message}");
        assert!(message.contains("line 1"), "{message}");
        // Never the value itself.
        assert!(!message.contains("super"), "{message}");
    }

    /// Round-3 finding 1a: the same rule for a *multi-line* value. The check
    /// used to be skipped whenever the value contained a newline, so
    /// `PRIVATE_KEY="a\nb"SECRETTAIL` imported as `a\nb` and reported success
    /// while the tail was neither imported nor left where anyone would look for
    /// it.
    #[test]
    fn parse_dotenv_refuses_a_multiline_value_partly_outside_its_quotes() {
        let error =
            parse_dotenv("PRIVATE_KEY=\"line one\nline two\"SECRETTAIL\nOTHER=fine\n").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("PRIVATE_KEY"), "{message}");
        assert!(message.contains("closing quote"), "{message}");
        // Never the value, nor the stranded tail.
        assert!(!message.contains("line one"), "{message}");
        assert!(!message.contains("SECRETTAIL"), "{message}");
    }

    /// Finding 22, at the import boundary: a value nothing can ever inject must
    /// not be pushed to a provider and reported as imported.
    #[test]
    fn parse_dotenv_refuses_a_value_containing_a_nul() {
        let error = parse_dotenv("BAD=before\0after\nGOOD=fine\n").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("BAD"), "{message}");
        assert!(message.contains("NUL"), "{message}");
        assert!(!message.contains("after"), "the value leaked: {message}");
    }

    #[test]
    fn parse_dotenv_still_rejects_a_line_that_is_not_an_assignment() {
        let error = parse_dotenv("KEY=value\nnot an assignment\n").unwrap_err();
        assert!(
            error.to_string().contains("not a KEY=value assignment"),
            "{error}"
        );
    }

    #[test]
    fn parse_dotenv_rejects_invalid_keys() {
        let error = parse_dotenv("1KEY=value").unwrap_err();
        assert!(error.to_string().contains("valid env var name"));
    }
}
