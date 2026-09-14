use std::collections::BTreeMap;

use anyhow::Result;
use ggshield_secrets::{Provider, SecretStore};
use secrecy::SecretString;

use crate::commands::shared::{
    Scope, confirm_existing_fields, field_count, prompt_secret, secret_path,
};
use crate::env::{validate_env_key, validate_env_value};

#[derive(clap::Args)]
pub(crate) struct Args {
    /// Secret manager to write to.
    #[arg(long, value_enum)]
    provider: Provider,
    /// Full path to the secret.
    /// Vault: <mount>/<secret path>; 1Password: <vault>/<item>;
    /// file: the dotenv file to write (default: .env).
    #[arg(long)]
    path: Option<String>,
    /// Which file to write, for the file provider (default: project).
    #[arg(long, value_enum)]
    scope: Option<Scope>,
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
    for key in &args.keys {
        validate_env_key(key)?;
    }
    if args.plain && args.provider != Provider::File {
        anyhow::bail!("--plain only applies to the file provider");
    }
    let path = secret_path(args.provider, args.path, args.scope)?;
    let store = SecretStore::builder(args.provider)
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
        // Prompted, never taken from argv: a value passed as an argument ends
        // up in shell history and in every process listing on the machine.
        let value = prompt_secret(key, args.expose, args.allow_empty)?;
        let value = SecretString::from(value);
        // The name was checked above; the value has to be checked too. A NUL is
        // a valid UTF-8 code point, so it survives being piped in here and
        // stored as perfectly good ciphertext — and then every attempt to use
        // it fails, because neither `run` nor the shell hook can put a NUL in a
        // child's environment. Refused where it arrives, so the report of
        // success is not a lie about a value nothing can ever read back out.
        validate_env_value(key, &value)?;
        fields.insert(key.clone(), value);
    }
    for warning in store.set_secrets_with_warnings(&path, &fields, confirmed.as_ref())? {
        eprintln!("warning: {warning}");
    }
    // Names, count and path only — never a value.
    eprintln!(
        "set {} at {path}: {}",
        field_count(fields.len()),
        fields.keys().cloned().collect::<Vec<_>>().join(", ")
    );
    Ok(())
}
