use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ggshield_secrets::{Provider, SecretStore};

use crate::commands::shared::{confirm_existing_fields, ensure_not_file_provider, field_count};
use crate::env::parse_dotenv;

#[derive(clap::Args)]
pub(crate) struct Args {
    /// Secret manager to write to.
    #[arg(long, value_enum)]
    provider: Provider,
    /// Full path to the secret.
    /// Vault: <mount>/<secret path>; 1Password: <vault>/<item>.
    #[arg(long)]
    path: String,
    /// Overwrite existing fields without asking.
    #[arg(long)]
    yes: bool,
    /// Dotenv file to read. Reads stdin when omitted.
    input: Option<PathBuf>,
}

pub(crate) fn execute(args: Args) -> Result<()> {
    ensure_not_file_provider(args.provider, "import")?;
    let contents = read_import_input(args.input.as_deref())?;
    let fields = parse_dotenv(&contents)?;
    let keys = fields.keys().cloned().collect::<Vec<_>>();
    let store = SecretStore::builder(args.provider)
        .env_override(false)
        .build()?;
    if !args.yes {
        confirm_existing_fields(&store, &args.path, &keys)?;
    }
    store.set_secrets(&args.path, &fields)?;
    eprintln!("imported {} at {}", field_count(fields.len()), args.path);
    Ok(())
}

fn read_import_input(input: Option<&Path>) -> Result<String> {
    match input {
        Some(path) => {
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
        }
        None => {
            if std::io::stdin().is_terminal() {
                bail!(
                    "no import input provided; pass a dotenv file or pipe KEY=value lines on stdin"
                )
            }
            let mut contents = String::new();
            std::io::stdin()
                .read_to_string(&mut contents)
                .context("reading stdin")?;
            Ok(contents)
        }
    }
}
