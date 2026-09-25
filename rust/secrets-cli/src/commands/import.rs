use std::collections::BTreeMap;
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use ggshield_secrets::{Provider, ReadWarnings, SecretStore};
use secrecy::{ExposeSecret, SecretString};

use crate::commands::shared::{
    ScopeArgs, confirm_existing_fields, field_count, resolve_provider, write_path,
};
use crate::env::parse_dotenv;

/// Import dotenv `KEY=value` entries into a secret.
///
/// The way an existing `.env` becomes managed: read it, write every entry into
/// the target (encrypted, for the file provider), and with `--remove-source`
/// delete the file it came from once the write has succeeded.
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
    /// Store the values as readable plaintext instead of encrypting them.
    /// File provider only.
    #[arg(long)]
    plain: bool,
    /// Delete the file the entries came from, once they are written.
    #[arg(long)]
    remove_source: bool,
    /// Overwrite existing fields without asking.
    #[arg(long)]
    yes: bool,
    /// Dotenv file to read. Reads stdin when omitted.
    input: Option<PathBuf>,
}

pub(crate) fn execute(args: Args) -> Result<()> {
    let provider = resolve_provider(args.provider)?;
    if args.plain && provider != Provider::File {
        bail!("--plain only applies to the file provider");
    }
    ensure!(
        !(args.remove_source && args.input.is_none()),
        "--remove-source needs a file to remove; the entries came from stdin"
    );
    if args.remove_source
        && let Some(input) = args.input.as_deref()
    {
        refuse_removing_a_symlink(input)?;
    }
    let path = write_path(provider, args.path, args.scope.get())?;
    if let Some(input) = args.input.as_deref() {
        refuse_importing_a_file_into_itself(input, &path)?;
    }
    let contents = read_import_input(args.input.as_deref())?;
    let mut fields = parse_dotenv(&contents)?;
    let sealed = sealed_fields(&fields);
    if !sealed.is_empty() {
        let opened = open_sealed(args.input.as_deref(), &sealed)?;
        replace_sealed(&mut fields, &sealed, opened)?;
    }
    let keys = fields.keys().cloned().collect::<Vec<_>>();
    let store = SecretStore::builder(provider)
        .env_override(false)
        .file_encrypt(!args.plain)
        .build()?;
    if !args.yes {
        confirm_existing_fields(&store, &path, &keys)?;
    }
    store.set_secrets(&path, &fields)?;
    eprintln!("imported {} at {path}", field_count(fields.len()));

    // Only after the write succeeded, or the values are lost.
    if let Some(input) = args.input.as_deref() {
        if args.remove_source {
            remove_if_unchanged(input, &contents)?;
            eprintln!("removed {}", input.display());
        } else {
            eprintln!(
                "{} still holds the values in cleartext; remove it, or pass --remove-source next \
                 time",
                input.display()
            );
        }
    }
    Ok(())
}

/// Removing a link would leave the values in its target while saying they were removed.
fn refuse_removing_a_symlink(input: &Path) -> Result<()> {
    let is_link =
        std::fs::symlink_metadata(input).is_ok_and(|metadata| metadata.file_type().is_symlink());
    ensure!(
        !is_link,
        "{} is a symbolic link; --remove-source would delete the link and leave the values in \
         its target. Import the target instead, or drop --remove-source",
        input.display()
    );
    Ok(())
}

/// An editor saving between the read and here would lose values that were never imported.
fn remove_if_unchanged(input: &Path, imported: &str) -> Result<()> {
    let current =
        std::fs::read(input).with_context(|| format!("re-reading {}", input.display()))?;
    ensure!(
        current == imported.as_bytes(),
        "{} changed after it was read, so it was not removed: it may hold values that were not \
         imported. Check it, then import it again or remove it yourself",
        input.display()
    );
    std::fs::remove_file(input).with_context(|| format!("removing {}", input.display()))
}

const SEALED_PREFIX: &str = "gitguardian:";

/// Values `encrypt` sealed with this device's key.
fn sealed_fields(fields: &BTreeMap<String, SecretString>) -> Vec<String> {
    fields
        .iter()
        .filter(|(_, value)| value.expose_secret().starts_with(SEALED_PREFIX))
        .map(|(key, _)| key.clone())
        .collect()
}

fn open_sealed(
    input: Option<&Path>,
    sealed: &[String],
) -> Result<(BTreeMap<String, SecretString>, ReadWarnings)> {
    let Some(input) = input else {
        bail!(
            "encrypted values on stdin ({}); pass the file instead so they can be decrypted \
             before import",
            sealed.join(", ")
        );
    };
    let input_path = input
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("{} is not valid UTF-8", input.display()))?;
    SecretStore::builder(Provider::File)
        .build()?
        .get_secrets_from_file(input_path)
        .with_context(|| format!("decrypting the encrypted values in {}", input.display()))
}

fn replace_sealed(
    fields: &mut BTreeMap<String, SecretString>,
    sealed: &[String],
    (mut opened, warnings): (BTreeMap<String, SecretString>, ReadWarnings),
) -> Result<()> {
    let mut unopened = Vec::new();
    for key in sealed {
        match opened.remove(key) {
            Some(value) if !value.expose_secret().starts_with(SEALED_PREFIX) => {
                fields.insert(key.clone(), value);
            }
            _ => unopened.push(key.clone()),
        }
    }
    if !unopened.is_empty() {
        for warning in &warnings.unreadable {
            eprintln!("warning: {warning}");
        }
        bail!(
            "refusing to import: {} cannot be decrypted on this device, so only ciphertext \
             would be imported",
            unopened.join(", ")
        );
    }
    Ok(())
}

/// Refuse `import --path .env .env`, which would otherwise read a file, write
/// it back and — with `--remove-source` — delete what it just wrote.
fn refuse_importing_a_file_into_itself(input: &Path, target: &str) -> Result<()> {
    let target = Path::new(target);
    let same = match (std::fs::canonicalize(input), std::fs::canonicalize(target)) {
        (Ok(input), Ok(target)) => input == target,
        _ => input == target,
    };
    ensure!(
        !same,
        "{} is both the source and the target; name a different file or scope",
        input.display()
    );
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

#[cfg(test)]
// A failed unwrap is the assertion failing; the lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> BTreeMap<String, SecretString> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), SecretString::from(value.to_string())))
            .collect()
    }

    #[test]
    fn sealed_values_are_replaced_by_their_plaintext() {
        let mut imported = fields(&[("SEALED", "gitguardian:AAAA"), ("PLAIN", "p")]);
        let sealed = sealed_fields(&imported);
        assert_eq!(sealed, ["SEALED".to_string()]);
        let opened = fields(&[("SEALED", "opened"), ("PLAIN", "p")]);
        replace_sealed(&mut imported, &sealed, (opened, ReadWarnings::default())).unwrap();
        assert_eq!(imported["SEALED"].expose_secret(), "opened");
        assert_eq!(imported["PLAIN"].expose_secret(), "p");
    }

    /// Never push ciphertext only this device can open.
    #[test]
    fn a_sealed_value_that_cannot_be_decrypted_is_refused() {
        let mut imported = fields(&[("SEALED", "gitguardian:AAAA"), ("PLAIN", "p")]);
        let sealed = sealed_fields(&imported);
        let opened = fields(&[("PLAIN", "p")]);
        let error =
            replace_sealed(&mut imported, &sealed, (opened, ReadWarnings::default())).unwrap_err();
        assert!(error.to_string().contains("SEALED"), "{error}");
    }

    #[test]
    fn sealed_values_on_stdin_are_refused() {
        let error = open_sealed(None, &["SEALED".to_string()]).unwrap_err();
        assert!(error.to_string().contains("pass the file"), "{error}");
    }

    #[test]
    fn a_source_edited_after_the_read_is_kept() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join(".env");
        std::fs::write(&input, "A=1\nB=2\n").unwrap();
        let error = remove_if_unchanged(&input, "A=1\n").unwrap_err();
        assert!(error.to_string().contains("not removed"), "{error}");
        assert!(input.exists());
        remove_if_unchanged(&input, "A=1\nB=2\n").unwrap();
        assert!(!input.exists());
    }

    #[cfg(unix)]
    #[test]
    fn remove_source_refuses_a_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("real.env");
        std::fs::write(&target, "A=1\n").unwrap();
        let link = directory.path().join(".env");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let error = refuse_removing_a_symlink(&link).unwrap_err();
        assert!(error.to_string().contains("symbolic link"), "{error}");
        refuse_removing_a_symlink(&target).unwrap();
    }
}
