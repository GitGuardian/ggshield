use std::io::{IsTerminal, Write};

use anyhow::Result;
use ggshield_secrets::{Provider, SecretStore};

use crate::commands::shared::secret_path;
use crate::output::show;

#[derive(clap::Args)]
pub(crate) struct Args {
    /// Secret manager to read from.
    #[arg(long, value_enum)]
    provider: Provider,
    /// Full path to the secret.
    /// Vault: <mount>/<secret path>; 1Password: <vault>/<item>;
    /// file: the project dotenv file to read (default: .env).
    #[arg(long)]
    path: Option<String>,
    /// Extract a single field from a JSON-map secret.
    #[arg(long)]
    field: Option<String>,
    /// Print secret values instead of redacting them. Values are also
    /// exposed automatically when output is piped or redirected.
    #[arg(long)]
    expose: bool,
}

pub(crate) fn execute(args: Args) -> Result<()> {
    let path = secret_path(args.provider, args.path, None)?;
    // `get` inspects what the provider holds; the environment must not be
    // able to shadow it.
    let store = SecretStore::builder(args.provider)
        .env_override(false)
        .build()?;

    // Redact on an interactive terminal (scrollback, screen-shares); expose
    // when explicitly asked, or when piped/redirected so scripts still work.
    let mut out = std::io::stdout().lock();
    let expose = args.expose || !out.is_terminal();

    // `writeln!` rather than `println!`: a broken pipe is handled by the
    // SIGPIPE reset in main(), and any other write error (e.g. disk full)
    // bubbles up instead of panicking.
    match args.field.as_deref() {
        Some(name) => {
            let value = store.get_secret(&path, name)?;
            writeln!(out, "{}", show(&value, expose))?;
        }
        None => {
            let (fields, warnings) = store.get_secrets_with_warnings(&path)?;
            // On stderr, so a redirected or piped stdout still holds only the
            // values — but the user is told which fields are missing and why.
            // `get` reports what it read and warns about the rest, deliberately:
            // it prints values rather than injecting them, so a partial answer
            // the user can see is more useful than no answer. `run` refuses the
            // same file.
            for warning in warnings.messages() {
                eprintln!("warning: {warning}");
            }
            for (key, value) in &fields {
                // A value containing a newline printed bare is indistinguishable
                // from several variables: one multi-line secret reads as three
                // assignments. Quote those so the output stays parseable as the
                // dotenv it looks like. Single-line values are printed as before.
                let shown = show(value, expose);
                if shown.contains('\n') || shown.contains('\r') {
                    writeln!(out, "{key}={}", quote_for_display(shown))?;
                } else {
                    writeln!(out, "{key}={shown}")?;
                }
            }
        }
    }
    out.flush()?;
    Ok(())
}

/// Wrap a multi-line value so `KEY=value` output cannot be misread as several
/// assignments. Single quotes when the value allows it (nothing is expanded
/// inside them), double quotes with escaped newlines otherwise.
fn quote_for_display(value: &str) -> String {
    if !value.contains('\'') {
        return format!("'{value}'");
    }
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
