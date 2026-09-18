use std::collections::BTreeSet;

use anyhow::{Result, bail};
use ggshield_secrets::{EncryptOutcome, Provider, SecretStore};

use crate::commands::shared::{Scope, confirm, field_count, secret_path};
use crate::env::validate_env_key;

/// Encrypt the plaintext values already in a dotenv file, in place.
///
/// The counterpart to `set` for values that are already on disk: a multi-line
/// key that `set` cannot read from a prompt is written into the file (or arrives
/// there from a vendor's download) and encrypted here. Comments, ordering and
/// quoting are preserved, and values that are already encrypted are untouched,
/// so running it twice is a no-op.
#[derive(clap::Args)]
pub(crate) struct Args {
    /// Dotenv file to rewrite (default: .env).
    #[arg(long)]
    path: Option<String>,
    /// Which file to rewrite, git-config style (default: project).
    #[arg(long, value_enum)]
    scope: Option<Scope>,
    /// Encrypt without asking first.
    #[arg(long)]
    yes: bool,
    /// Encrypt every plaintext value in the file.
    ///
    /// Required to encrypt without naming variables: there is no schema saying
    /// which values are secret, so a bare `encrypt` would also seal ordinary
    /// config like PORT — readable today, opaque and device-locked afterwards.
    #[arg(long, conflicts_with = "keys")]
    all: bool,
    /// Variables to encrypt. Pass --all instead to take every plaintext value.
    keys: Vec<String>,
}

pub(crate) fn execute(args: Args) -> Result<()> {
    for key in &args.keys {
        validate_env_key(key)?;
    }
    if args.keys.is_empty() && !args.all {
        bail!(
            "name the variables to encrypt, or pass --all to encrypt every plaintext value. \
             Without a name this would also seal ordinary config, which is readable today"
        );
    }
    // Values live in a file only for the file provider; everywhere else the
    // provider already holds the secret.
    let path = secret_path(Provider::File, args.path, args.scope)?;
    let only = (!args.keys.is_empty()).then(|| args.keys.iter().cloned().collect::<BTreeSet<_>>());

    let store = SecretStore::builder(Provider::File).build()?;

    // A name that is not in the file is a typo, and reporting "nothing to
    // encrypt" for it would read as success.
    if !args.keys.is_empty() {
        let present = store.field_names(&path)?;
        let unknown = args
            .keys
            .iter()
            .filter(|key| !present.contains(key))
            .cloned()
            .collect::<Vec<_>>();
        if !unknown.is_empty() {
            bail!("{path} does not set {}", unknown.join(", "));
        }
    }

    // What the second pass is allowed to touch. `--yes` asked no question, so
    // it is whatever the user named (or everything); an answered prompt narrows
    // it to the names in the answer. See [`write_scope`].
    let mut answered: Option<EncryptOutcome> = None;

    if !args.yes {
        // Encrypting is not reversible for anyone without this device's key, so
        // say what is about to become unreadable elsewhere before doing it.
        let preview = store.encrypt_in_place(&path, only.as_ref(), true)?;
        if preview.encrypted.is_empty() {
            report(&path, &preview);
            return Ok(());
        }
        eprintln!(
            "{path}: {} will be encrypted with this device's key and become unreadable on any \
             other machine: {}",
            field_count(preview.encrypted.len()),
            preview.encrypted.join(", ")
        );
        confirm()?;
        answered = Some(preview);
    }

    let allowed = write_scope(only.as_ref(), answered.as_ref());
    let outcome = store.encrypt_in_place(&path, allowed.as_ref(), false)?;
    report(&path, &outcome);
    Ok(())
}

/// Which names the write pass may touch.
///
/// The preview and the write are two locked passes with a prompt between them.
/// Holding one lock across the prompt is the alternative, and it is worse — an
/// unanswered prompt would block every other ggshield process on the file
/// for as long as the terminal sits there. So the answer is not to close the
/// window but to bound what the answer authorises.
///
/// `--all` used to hand the write no restriction at all. A `PORT=3000` appended
/// by another process while the prompt sat there was sealed too: configuration
/// that was portable a moment ago, device-local afterwards, and never named in
/// the list the user said yes to. The names the preview returned *are* that
/// list, so they become the bound. The already-encrypted ones come along so the
/// write can still report them.
///
/// `None` — no bound — is therefore only ever right when no question was asked.
fn write_scope(
    only: Option<&BTreeSet<String>>,
    answered: Option<&EncryptOutcome>,
) -> Option<BTreeSet<String>> {
    match answered {
        Some(preview) => Some(
            preview
                .encrypted
                .iter()
                .chain(preview.already_encrypted.iter())
                .cloned()
                .collect(),
        ),
        None => only.cloned(),
    }
}

/// Names and counts only — never a value.
fn report(path: &str, outcome: &EncryptOutcome) {
    for warning in &outcome.warnings {
        eprintln!("warning: {warning}");
    }
    if outcome.encrypted.is_empty() {
        eprintln!("nothing to encrypt at {path}: no plaintext values");
    } else {
        eprintln!(
            "encrypted {} at {path}: {}",
            field_count(outcome.encrypted.len()),
            outcome.encrypted.join(", ")
        );
    }
    if !outcome.already_encrypted.is_empty() {
        eprintln!(
            "left {} already encrypted",
            field_count(outcome.already_encrypted.len())
        );
    }
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn outcome(encrypted: &[&str], already: &[&str]) -> EncryptOutcome {
        EncryptOutcome {
            encrypted: encrypted.iter().map(|name| name.to_string()).collect(),
            already_encrypted: already.iter().map(|name| name.to_string()).collect(),
            warnings: Vec::new(),
        }
    }

    /// Finding 21: an answered prompt authorises the names it showed, and only
    /// those. `--all` used to leave the write unbounded, so a field another
    /// process appended while the prompt waited was sealed without ever
    /// appearing in the list the user agreed to.
    #[test]
    fn an_answered_prompt_bounds_the_write_to_what_it_showed() {
        let preview = outcome(&["API_KEY"], &["OLD"]);
        let allowed = write_scope(None, Some(&preview)).expect("--all must still be bounded");
        assert!(allowed.contains("API_KEY"));
        // Carried so the write can still report it as left alone.
        assert!(allowed.contains("OLD"));
        // The field that appeared after the preview is not in scope.
        assert!(!allowed.contains("PORT"), "{allowed:?}");
    }

    /// `--yes` asked nothing, so there is nothing to hold it to beyond what the
    /// user named on the command line.
    #[test]
    fn yes_keeps_the_scope_the_user_asked_for() {
        assert_eq!(write_scope(None, None), None);
        let named = BTreeSet::from(["SEAL".to_string()]);
        assert_eq!(write_scope(Some(&named), None), Some(named));
    }
}
