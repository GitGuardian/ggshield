use std::io::Write;

use anyhow::Result;
use ggshield_secrets::{Provider, SecretStore};

use crate::commands::shared::{
    ScopeArgs, ensure_explicit_path_exists, resolve_provider, secret_path,
};

/// List the names a secret sets, without their values.
///
/// Nothing is decrypted, so this also works for values encrypted on another
/// machine.
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
    #[command(flatten)]
    scope: ScopeArgs,
    /// Say which scope each name came from (file provider): system, global,
    /// local or project.
    #[arg(long)]
    show_scope: bool,
}

pub(crate) fn execute(args: Args) -> Result<()> {
    let provider = resolve_provider(args.provider)?;
    let scope = args.scope.get();
    let explicit_path = args.path.is_some();
    let path = secret_path(provider, args.path, scope)?;
    if explicit_path {
        ensure_explicit_path_exists(provider, &path)?;
    }
    let store = SecretStore::builder(provider).env_override(false).build()?;

    let names: Vec<(String, Option<String>)> = match scope {
        Some(scope) => store
            .field_names(&path)?
            .into_iter()
            .map(|name| (name, Some(scope.to_string())))
            .collect(),
        None if provider == Provider::File => store
            .field_scopes(&path)?
            .into_iter()
            .map(|(name, scope)| (name, Some(scope)))
            .collect(),
        None => store
            .field_names(&path)?
            .into_iter()
            .map(|name| (name, None))
            .collect(),
    };

    let mut out = std::io::stdout().lock();
    for (name, scope) in names {
        match scope.filter(|_| args.show_scope) {
            Some(scope) => writeln!(out, "{name}  # {scope}")?,
            None => writeln!(out, "{name}")?,
        }
    }
    out.flush()?;
    Ok(())
}
