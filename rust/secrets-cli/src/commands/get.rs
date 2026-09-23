use std::io::{IsTerminal, Write};

use anyhow::Result;
use ggshield_secrets::{Provider, SecretStore};

use crate::commands::shared::{
    ScopeArgs, ensure_explicit_path_exists, resolve_provider, secret_path,
};
use crate::output::show;

#[derive(clap::Args)]
pub(crate) struct Args {
    /// Secret manager to read from.
    /// Default: `secret.provider` in .gitguardian.yaml, else file.
    #[arg(long, value_enum)]
    provider: Option<Provider>,
    /// Full path to the secret.
    /// Vault: <mount>/<secret path>;
    /// file: the project dotenv file to read (default: .env).
    #[arg(long)]
    path: Option<String>,
    /// Extract a single field from a JSON-map secret.
    #[arg(long)]
    field: Option<String>,
    #[command(flatten)]
    scope: ScopeArgs,
    /// Print secret values instead of redacting them. Values are also
    /// exposed automatically when output is piped or redirected.
    #[arg(long)]
    expose: bool,
    /// Say which scope each value came from (file provider): system, global,
    /// local or project. A value the repository defines and this checkout overrides
    /// looks identical otherwise.
    #[arg(long)]
    show_scope: bool,
}

pub(crate) fn execute(args: Args) -> Result<()> {
    let provider = resolve_provider(args.provider)?;
    let explicit_path = args.path.is_some();
    let path = secret_path(provider, args.path, args.scope.get())?;
    if explicit_path {
        ensure_explicit_path_exists(provider, &path)?;
    }
    let one_scope = args.scope.get().is_some();
    // `get` inspects what the provider holds; the environment must not shadow it.
    let store = SecretStore::builder(provider).env_override(false).build()?;

    // Redact on a terminal (scrollback, screen-shares); piped output stays usable by scripts.
    let mut out = std::io::stdout().lock();
    let expose = args.expose || !out.is_terminal();

    // `writeln!`, not `println!`: write errors (disk full) surface instead of panicking.
    match args.field.as_deref() {
        Some(name) => {
            let value = if one_scope {
                store
                    .get_secrets_from_file(&path)?
                    .0
                    .remove(name)
                    .ok_or_else(|| anyhow::anyhow!("'{name}' is not set in {path}"))?
            } else {
                store.get_secret(&path, name)?
            };
            writeln!(out, "{}", show(&value, expose))?;
        }
        None => {
            let (fields, warnings) = if one_scope {
                store.get_secrets_from_file(&path)?
            } else {
                store.get_secrets_with_warnings(&path)?
            };
            let scopes = if args.show_scope {
                store.field_scopes(&path)?
            } else {
                Default::default()
            };
            // Deliberately partial: `get` only prints, so it warns where `run` refuses.
            // Stderr keeps piped stdout to values only.
            for warning in warnings.messages() {
                eprintln!("warning: {warning}");
            }
            for (key, value) in &fields {
                let shown = show(value, expose);
                let scope = match scopes.get(key) {
                    Some(scope) => format!("  # {scope}"),
                    None => String::new(),
                };
                // Unquoted, one multi-line value would read back as several assignments.
                if shown.contains('\n') || shown.contains('\r') {
                    writeln!(out, "{key}={}{scope}", quote_for_display(shown))?;
                } else {
                    writeln!(out, "{key}={shown}{scope}")?;
                }
            }
        }
    }
    out.flush()?;
    Ok(())
}

/// Single quotes when the value allows it (nothing expands inside them),
/// otherwise double quotes with escapes.
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
