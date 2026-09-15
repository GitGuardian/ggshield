use std::collections::BTreeMap;

use anyhow::Result;
use ggshield_secrets::{Provider, SecretStore};
use secrecy::SecretString;

use crate::commands::shared::{
    ScopeArgs, confirm_existing_fields, field_count, prompt_secret, resolve_provider, write_path,
};
use crate::env::{validate_env_key, validate_env_value};

#[derive(clap::Args)]
pub(crate) struct Args {
    /// Secret manager to write to.
    /// Default: `secret.provider` in .gitguardian.yaml, else file.
    #[arg(long, value_enum)]
    provider: Option<Provider>,
    /// Full path to the secret.
    /// Vault: <mount>/<secret path>;
    /// file: the dotenv file to write (default: the repository store,
    /// or .env outside a repository).
    #[arg(long)]
    path: Option<String>,
    #[command(flatten)]
    scope: ScopeArgs,
    /// Store the value as readable plaintext instead of encrypting it.
    /// File provider only.
    #[arg(long)]
    plain: bool,
    /// Show secret values while typing instead of using a redacted prompt.
    #[arg(long)]
    expose: bool,
    /// Overwrite existing fields without asking.
    #[arg(long)]
    yes: bool,
    /// Accept an empty value. Without this an empty value is refused, because
    /// the only thing it can do is replace what is stored with nothing.
    #[arg(long)]
    allow_empty: bool,
    /// Environment variable names to set.
    ///
    /// One value is read per name — from the terminal, or one line of stdin per
    /// name in the order given. Values are therefore single-line: a value that
    /// contains a newline, such as a PEM private key, cannot be entered through
    /// `set`, even though the file format itself round-trips one correctly.
    #[arg(required = true)]
    keys: Vec<String>,
}

pub(crate) fn execute(args: Args) -> Result<()> {
    let provider = resolve_provider(args.provider)?;
    for key in &args.keys {
        validate_env_key(key)?;
    }
    if args.plain && provider != Provider::File {
        anyhow::bail!("--plain only applies to the file provider");
    }
    let path = write_path(provider, args.path, args.scope.get())?;
    let store = SecretStore::builder(provider)
        .env_override(false)
        .file_encrypt(!args.plain)
        .build()?;
    // The names the user is shown, so the write can refuse if the file gained
    // one of the others between this question and the lock it takes.
    let confirmed = if args.yes {
        None
    } else {
        Some(confirm_existing_fields(&store, &path, &args.keys)?)
    };
    let mut fields = BTreeMap::new();
    for key in &args.keys {
        // Never from argv: that lands in shell history and every process listing.
        let value = prompt_secret(key, args.expose, args.allow_empty)?;
        let value = SecretString::from(value);
        // A NUL encrypts fine but can never be injected by `run` or the hook,
        // so refuse it here rather than report a useless success.
        validate_env_value(key, &value)?;
        fields.insert(key.clone(), value);
    }
    for warning in store.set_secrets_with_warnings(&path, &fields, confirmed.as_ref())? {
        eprintln!("warning: {warning}");
    }
    // Never a value.
    eprintln!(
        "set {} at {path}: {}",
        field_count(fields.len()),
        fields.keys().cloned().collect::<Vec<_>>().join(", ")
    );
    Ok(())
}
