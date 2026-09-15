use std::collections::BTreeSet;

use anyhow::{Result, bail, ensure};
use ggshield_secrets::{Provider, SecretError, SecretStore, user_scope_path};

use crate::commands::shared::{Scope, confirm, field_count, write_path};
use crate::env::validate_env_key;

/// Delete a provider secret, or selected fields from it.
///
/// For the file provider this removes variables from a dotenv file, leaving the
/// file, its comments, its blank lines and every other value exactly as they
/// were; `--all` empties the assignments rather than deleting the file, which
/// is what `rm` is for. Names are removed from the file you name and no other,
/// so a variable that only the user-scope file sets needs `--scope user`.
///
/// Nothing is decrypted, so a value encrypted on another machine can still be
/// removed here — but an encrypted value that is removed is gone: there is no
/// key escrow and no recovery.
#[derive(clap::Args)]
pub(crate) struct Args {
    /// Secret manager to delete from.
    #[arg(long, value_enum)]
    provider: Provider,
    /// Full path to the secret.
    /// Vault: <mount>/<secret path>; 1Password: <vault>/<item>;
    /// file: the dotenv file to edit (default: the repository store,
    /// or .env outside a repository).
    #[arg(long)]
    path: Option<String>,
    /// Which file to edit, for the file provider (default: repo in a git
    /// repository, project outside one).
    #[arg(long, value_enum)]
    scope: Option<Scope>,
    /// Skip confirmation.
    #[arg(long)]
    yes: bool,
    /// Delete the whole secret.
    /// For the file provider, every variable the file sets — the file itself,
    /// its comments and its blank lines are kept.
    #[arg(long)]
    all: bool,
    /// Environment variable names to delete.
    keys: Vec<String>,
}

pub(crate) fn execute(args: Args) -> Result<()> {
    ensure!(
        args.all || !args.keys.is_empty(),
        "pass field names to delete, or use --all to delete the whole secret"
    );
    ensure!(
        !args.all || args.keys.is_empty(),
        "--all cannot be combined with field names"
    );
    for key in &args.keys {
        validate_env_key(key)?;
    }
    let path = write_path(args.provider, args.path, args.scope)?;
    let store = SecretStore::builder(args.provider)
        .env_override(false)
        .build()?;
    if args.provider == Provider::File {
        return delete_from_file(&store, &path, args.all, &args.keys, args.yes);
    }
    delete_from_provider(&store, &path, args.all, &args.keys, args.yes)
}

/// Remove variables from a dotenv file.
///
/// Two phases with the confirmation between them, because the write lock cannot
/// be held across a prompt: `plan_delete` decides what would be removed and
/// records the state of the file it decided against, and `delete_planned`
/// refuses to write if that file has changed since. Everything that should stop
/// a delete — a missing file, ambiguous quoting, a name the file does not set, a
/// value that has swallowed other variables — is reported by the plan, before
/// the user is asked anything.
///
/// The plan reads the named file alone and decrypts nothing: `del KEY` cannot
/// report success for a `KEY` that only the user-scope file sets, and a value
/// sealed on another machine — the one you most need to be able to delete — does
/// not have to be readable here first.
fn delete_from_file(
    store: &SecretStore,
    path: &str,
    all: bool,
    keys: &[String],
    yes: bool,
) -> Result<()> {
    // A `BTreeSet`, so naming the same variable twice cannot inflate the count
    // the user is shown or make the second pass look like a concurrent writer.
    let only = (!all).then(|| keys.iter().cloned().collect::<BTreeSet<_>>());
    let plan = store.plan_delete(path, only.as_ref())?;

    // `--all` on a file that sets nothing is not an error, matching `encrypt`:
    // the requested state is the state it is already in. A file that is not
    // there at all is a different thing, and the plan has already refused it.
    if plan.targets.is_empty() {
        eprintln!("nothing to delete at {path}: it sets no variables");
        return Ok(());
    }

    // Read before the delete, so the notice below can be printed after it
    // without a second look at a file the delete may have just changed.
    let shadowed = user_scope_names(store, path, &plan.targets);

    if !yes {
        // Named, not counted. `--all` is the case where the user is least
        // likely to know what is in the file, so it is the case where the list
        // matters most.
        eprintln!(
            "{} will be deleted from {path}: {}. Comments, blank lines and every other value are \
             kept, and the file itself is not removed",
            field_count(plan.targets.len()),
            plan.targets.join(", ")
        );
        confirm()?;
    }

    let outcome = store.delete_planned(path, &plan)?;
    for warning in &outcome.warnings {
        eprintln!("warning: {warning}");
    }
    // What was removed, not what was planned. A name another process deleted
    // first is reported above as a warning, and claiming to have deleted it
    // here would be the tool taking credit for a change it did not make.
    if outcome.removed.is_empty() {
        eprintln!("nothing was removed from {path}");
        return Ok(());
    }
    eprintln!(
        "deleted {} from {path}: {}",
        field_count(outcome.removed.len()),
        outcome.removed.join(", ")
    );

    // The user-scope file is merged into every read of a project file, so a
    // name that is still set there is still resolvable — with an older value.
    // Someone rotating a leaked credential deletes the project value, sees
    // "deleted", and `run` keeps injecting the very value that must stop being
    // used. Only the names actually removed are worth saying this about.
    let unmasked = shadowed
        .iter()
        .filter(|name| outcome.removed.contains(name))
        .cloned()
        .collect::<Vec<_>>();
    if !unmasked.is_empty() {
        let (verb, whose) = if unmasked.len() == 1 {
            ("is", "its value")
        } else {
            ("are", "their values")
        };
        eprintln!(
            "note: {} {verb} still set by the user-scope file, so reads here now resolve to \
             {whose}. Use --scope user to delete there too",
            unmasked.join(", ")
        );
    }
    Ok(())
}

/// Which of `targets` the user-scope file also sets.
///
/// Best effort: this is a notice, not a guard, so a machine with no config
/// directory or an unreadable user file simply produces none. Never decrypts.
fn user_scope_names(store: &SecretStore, path: &str, targets: &[String]) -> Vec<String> {
    let Ok(user_path) = user_scope_path() else {
        return Vec::new();
    };
    let user_path = user_path.to_string_lossy().into_owned();
    // Deleting *from* the user file cannot leave a user-scope value behind it.
    if user_path == path {
        return Vec::new();
    }
    let Ok(names) = store.field_names(&user_path) else {
        return Vec::new();
    };
    targets
        .iter()
        .filter(|target| names.contains(target))
        .cloned()
        .collect()
}

/// Delete from a remote secret manager, where a path names a whole secret.
fn delete_from_provider(
    store: &SecretStore,
    path: &str,
    all: bool,
    keys: &[String],
    yes: bool,
) -> Result<()> {
    if all {
        // The preliminary read only feeds the confirmation message, so --yes
        // skips it too: a token with delete-but-not-read capability must be
        // able to delete a whole secret.
        let field_count_to_delete = if yes {
            None
        } else {
            let count = count_existing_fields(store, path)?;
            confirm_delete(path, true, keys, count)?;
            Some(count)
        };
        store.delete_secrets(path, &[])?;
        match field_count_to_delete {
            Some(count) => eprintln!("deleted secret at {path} ({})", field_count(count)),
            None => eprintln!("deleted secret at {path}"),
        }
    } else {
        ensure_fields_exist(store, path, keys)?;
        if !yes {
            confirm_delete(path, false, keys, keys.len())?;
        }
        store.delete_secrets(path, keys)?;
        eprintln!("deleted {} from {path}", field_count(keys.len()));
    }
    Ok(())
}

fn count_existing_fields(store: &SecretStore, path: &str) -> Result<usize> {
    match store.get_secrets(path) {
        Ok(existing) => Ok(existing.len()),
        Err(error) if SecretError::is_secret_not_found(&error) => {
            bail!("delete cancelled, no changes made: secret not found at {path}")
        }
        Err(error) => Err(error),
    }
}

fn ensure_fields_exist(store: &SecretStore, path: &str, keys: &[String]) -> Result<()> {
    let existing = match store.get_secrets(path) {
        Ok(existing) => existing,
        Err(error) if SecretError::is_secret_not_found(&error) => {
            bail!("{}", delete_cancelled_message(keys))
        }
        Err(error) => return Err(error),
    };
    let missing = missing_keys(existing.keys(), keys);
    if !missing.is_empty() {
        bail!("{}", delete_cancelled_message(&missing));
    }
    Ok(())
}

fn missing_keys<'a>(
    existing: impl Iterator<Item = &'a String>,
    requested: &'a [String],
) -> Vec<String> {
    let existing = existing.collect::<std::collections::BTreeSet<_>>();
    let mut missing = Vec::new();
    for key in requested {
        if !existing.contains(key) && !missing.contains(key) {
            missing.push(key.clone());
        }
    }
    missing
}

fn delete_cancelled_message(keys: &[String]) -> String {
    let noun = if keys.len() == 1 { "field" } else { "fields" };
    format!(
        "delete cancelled, no changes made: {noun} not found in secret: {}",
        keys.join(", ")
    )
}

fn confirm_delete(
    path: &str,
    all: bool,
    keys: &[String],
    field_count_to_delete: usize,
) -> Result<()> {
    if all {
        eprintln!(
            "secret at {path} will be deleted ({}).",
            field_count(field_count_to_delete)
        );
    } else {
        eprintln!("{} will be deleted from {path}.", keys.join(", "));
    }
    confirm()
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn missing_keys_are_deduplicated() {
        let existing = ["VAR".to_string(), "STRIPE".to_string()];
        let requested = [
            "VAR".to_string(),
            "AWS".to_string(),
            "AWS".to_string(),
            "GCP".to_string(),
        ];
        assert_eq!(
            missing_keys(existing.iter(), &requested),
            ["AWS".to_string(), "GCP".to_string()]
        );
    }

    #[test]
    fn delete_cancelled_message_is_pluralized() {
        assert_eq!(
            delete_cancelled_message(&["VAR".to_string()]),
            "delete cancelled, no changes made: field not found in secret: VAR"
        );
        assert_eq!(
            delete_cancelled_message(&["VAR".to_string(), "AWS".to_string()]),
            "delete cancelled, no changes made: fields not found in secret: VAR, AWS"
        );
    }

    #[test]
    fn delete_all_missing_secret_message_names_path() {
        let path = "secret/myapp";
        let error = format!("delete cancelled, no changes made: secret not found at {path}");
        assert_eq!(
            error,
            "delete cancelled, no changes made: secret not found at secret/myapp"
        );
    }
}
