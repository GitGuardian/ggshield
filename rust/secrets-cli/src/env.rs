use std::collections::BTreeMap;

use anyhow::{Result, bail, ensure};
use ggshield_secrets::dotenv::{Document, Line, QuoteProblem};
use secrecy::{ExposeSecret, SecretString};

/// Stricter than the file provider's reading: a line that is not an assignment
/// is an error, since the caller expects all of the file to be imported.
pub(crate) fn parse_dotenv(contents: &str) -> Result<BTreeMap<String, SecretString>> {
    let document = Document::parse(contents);
    match document.quote_problem() {
        Some(problem @ QuoteProblem::Unterminated { .. }) => bail!(
            "{problem}; fix it before importing, or the variables after it are swallowed into \
             one value"
        ),
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
                // Warn only for a disabled assignment; prose with '=' (a URL) is just a comment.
                if let Some(key) = commented_env_var(raw) {
                    eprintln!("warning: ignored commented env var '{key}' on line {line_number}");
                }
            }
            Line::Entry(entry) => {
                let value = SecretString::from(entry.value());
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

fn commented_env_var(raw: &str) -> Option<String> {
    let body = raw.trim().trim_start_matches('#').trim();
    let (key, _) = parse_env_assignment(body).ok().flatten()?;
    Some(key)
}

/// Never quotes the line: `postgres://u:pass@h/db?sslmode=require` would print the password.
fn not_an_assignment(raw: &str, line_number: usize) -> anyhow::Error {
    let content = raw.trim();
    let candidate = content
        .strip_prefix("export ")
        .unwrap_or(content)
        .trim_start();
    if let Some((key, _)) = candidate.split_once('=')
        && validate_env_key(key.trim()).is_err()
    {
        return anyhow::anyhow!(
            "line {line_number}: the text before '=' is not a valid env var name"
        );
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

/// `Command::env` rejects a NUL with an error naming neither variable nor file.
/// Never includes the value.
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
// A failed unwrap is the assertion failing; the lint targets shipped code.
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

    /// A value spanning several lines is one entry, not a parse error.
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

    /// Escapes and quoting resolve as the file provider reads them.
    #[test]
    fn parse_dotenv_resolves_quoting_like_the_provider_does() {
        let env = parse_dotenv("A='single'\nB=\"tab\\there\"\nC=bare\nD=\"do$llar\"\n").unwrap();
        assert_eq!(env.get("A").unwrap().expose_secret(), "single");
        assert_eq!(env.get("B").unwrap().expose_secret(), "tab\there");
        assert_eq!(env.get("C").unwrap().expose_secret(), "bare");
        assert_eq!(env.get("D").unwrap().expose_secret(), "do$llar");
    }

    /// A stray quote would swallow the variables after it.
    #[test]
    fn parse_dotenv_refuses_an_unterminated_quote() {
        let error = parse_dotenv("NOTE=\"oops\nKEY=value\n").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("never closed"), "{message}");
        assert!(message.contains("swallowed"), "{message}");
    }

    /// `API_KEY='super'password` must not import as `super`.
    #[test]
    fn parse_dotenv_refuses_a_value_that_is_partly_outside_its_quotes() {
        let error = parse_dotenv("API_KEY='super'password\nOTHER=fine\n").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("API_KEY"), "{message}");
        assert!(message.contains("closing quote"), "{message}");
        assert!(message.contains("line 1"), "{message}");
        assert!(!message.contains("super"), "{message}");
    }

    /// The same rule holds for a multi-line value.
    #[test]
    fn parse_dotenv_refuses_a_multiline_value_partly_outside_its_quotes() {
        let error =
            parse_dotenv("PRIVATE_KEY=\"line one\nline two\"SECRETTAIL\nOTHER=fine\n").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("PRIVATE_KEY"), "{message}");
        assert!(message.contains("closing quote"), "{message}");
        assert!(!message.contains("line one"), "{message}");
        assert!(!message.contains("SECRETTAIL"), "{message}");
    }

    /// A value nothing can inject is refused at import.
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
    fn parse_dotenv_does_not_echo_an_invalid_line() {
        let error = parse_dotenv("A=1\npostgres://u:S3cret@h/db?sslmode=require\n").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("line 2"), "{message}");
        assert!(!message.contains("S3cret"), "the value leaked: {message}");
    }

    #[test]
    fn parse_dotenv_rejects_invalid_keys() {
        let error = parse_dotenv("1KEY=value").unwrap_err();
        assert!(error.to_string().contains("valid env var name"));
    }
}
