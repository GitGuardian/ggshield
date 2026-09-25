use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail, ensure};
use ggshield_secrets::{
    DEFAULT_PROJECT_PATH, Provider, SecretError, SecretStore, repo_scope_path, system_scope_path,
    user_scope_path,
};

use crate::commands::shared::{
    Scope, ScopeArgs, confirm, field_count, resolve_provider, write_path,
};
use crate::env::validate_env_key;

/// Remove a provider secret, or selected fields from it.
///
/// For the file provider this removes variables from a dotenv file, leaving the
/// file, its comments, its blank lines and every other value exactly as they
/// were; `--all` empties the assignments rather than deleting the file, which
/// is what `rm` is for. Names are removed from the file you name and no other,
/// so a variable that only the user-scope file sets needs `--global`.
///
/// Nothing is decrypted, so a value encrypted on another machine can still be
/// removed here — but an encrypted value that is removed is gone: there is no
/// key escrow and no recovery.
#[derive(clap::Args)]
pub(crate) struct Args {
    /// Secret manager to delete from.
    /// Default: `secret.provider` in .gitguardian.yaml, else file.
    #[arg(long, value_enum)]
    provider: Option<Provider>,
    /// Full path to the secret.
    /// Vault: <mount>/<secret path>;
    /// file: the dotenv file to edit (default: the repository store,
    /// or .env outside a repository).
    #[arg(long)]
    path: Option<String>,
    #[command(flatten)]
    scope: ScopeArgs,
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
    let provider = resolve_provider(args.provider)?;
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
    let path = write_path(provider, args.path, args.scope.get())?;
    let store = SecretStore::builder(provider).env_override(false).build()?;
    if provider == Provider::File {
        return delete_from_file(&store, &path, args.all, &args.keys, args.yes);
    }
    delete_from_provider(&store, &path, args.all, &args.keys, args.yes)
}

/// Plan, prompt, then write: the lock cannot be held across a prompt, so
/// `delete_planned` refuses if the file changed since `plan_delete` read it.
fn delete_from_file(
    store: &SecretStore,
    path: &str,
    all: bool,
    keys: &[String],
    yes: bool,
) -> Result<()> {
    // Deduplicated, or a repeated name would look like a concurrent writer.
    let only = (!all).then(|| keys.iter().cloned().collect::<BTreeSet<_>>());
    let plan = store.plan_delete(path, only.as_ref())?;

    if plan.targets.is_empty() {
        eprintln!("nothing to delete at {path}: it sets no variables");
        return Ok(());
    }

    if !yes {
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
    // What was removed, not what was planned: another process may have won a race.
    if outcome.removed.is_empty() {
        eprintln!("nothing was removed from {path}");
        return Ok(());
    }
    eprintln!(
        "deleted {} from {path}: {}",
        field_count(outcome.removed.len()),
        outcome.removed.join(", ")
    );

    // Another scope's value still resolves after this delete, so a rotated leaked
    // credential would keep being injected by `run`.
    for (scope, names) in other_scopes_setting(store, path, &outcome.removed) {
        let verb = if names.len() == 1 { "is" } else { "are" };
        eprintln!(
            "note: {} {verb} still set in the {scope} scope. Use --{scope} to delete there too",
            names.join(", ")
        );
    }
    Ok(())
}

/// Most specific first, as reads resolve them.
fn scope_paths() -> Vec<(Scope, Option<String>)> {
    [
        (Scope::Project, Some(PathBuf::from(DEFAULT_PROJECT_PATH))),
        (Scope::Local, repo_scope_path(Path::new("."))),
        (Scope::Global, user_scope_path().ok()),
        (Scope::System, system_scope_path()),
    ]
    .into_iter()
    .map(|(scope, path)| (scope, path.map(|path| path.to_string_lossy().into_owned())))
    .collect()
}

/// Best effort: a notice, not a guard. Never decrypts.
fn other_scopes_setting(
    store: &SecretStore,
    path: &str,
    names: &[String],
) -> Vec<(Scope, Vec<String>)> {
    scopes_setting(store, &scope_paths(), path, names)
}

/// The scopes whose value for one of `names` wins over the one `path` holds.
pub(crate) fn scopes_shadowing(
    store: &SecretStore,
    path: &str,
    names: &[String],
) -> Vec<(Scope, Vec<String>)> {
    shadowing(store, &scope_paths(), path, names)
}

fn shadowing(
    store: &SecretStore,
    scopes: &[(Scope, Option<String>)],
    path: &str,
    names: &[String],
) -> Vec<(Scope, Vec<String>)> {
    let Some(own) = scopes
        .iter()
        .position(|(_, scope_path)| scope_path.as_deref() == Some(path))
    else {
        // A `--path` file is read as the project layer: nothing outranks it.
        return Vec::new();
    };
    scopes_setting(store, &scopes[..own], path, names)
}

fn scopes_setting(
    store: &SecretStore,
    scopes: &[(Scope, Option<String>)],
    path: &str,
    names: &[String],
) -> Vec<(Scope, Vec<String>)> {
    scopes
        .iter()
        .filter_map(|(scope, scope_path)| {
            let scope_path = scope_path.as_deref()?;
            if scope_path == path {
                return None;
            }
            let set = store.field_names(scope_path).ok()?;
            let still = names
                .iter()
                .filter(|name| set.contains(name))
                .cloned()
                .collect::<Vec<_>>();
            (!still.is_empty()).then_some((*scope, still))
        })
        .collect()
}

fn delete_from_provider(
    store: &SecretStore,
    path: &str,
    all: bool,
    keys: &[String],
    yes: bool,
) -> Result<()> {
    if all {
        // Skipped with --yes: a delete-but-not-read token must still work.
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
// A failed unwrap is the assertion failing; the lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn scopes_in(directory: &Path) -> Vec<(Scope, Option<String>)> {
        [
            (Scope::Project, "project.env"),
            (Scope::Local, "repo.env"),
            (Scope::Global, "user.env"),
        ]
        .into_iter()
        .map(|(scope, name)| {
            let path = directory.join(name).to_string_lossy().into_owned();
            (scope, Some(path))
        })
        .chain([(Scope::System, None)])
        .collect()
    }

    /// Only a more specific scope shadows a write; a less specific one does not.
    #[test]
    fn a_more_specific_scope_shadows_a_write() {
        let directory = tempfile::tempdir().unwrap();
        let scopes = scopes_in(directory.path());
        let path = |index: usize| scopes[index].1.clone().unwrap();
        std::fs::write(path(0), "API_KEY=old\nOTHER=1\n").unwrap();
        std::fs::write(path(1), "API_KEY=new\n").unwrap();
        std::fs::write(path(2), "API_KEY=user\n").unwrap();
        let store = SecretStore::builder(Provider::File).build().unwrap();
        let names = ["API_KEY".to_string(), "UNSET".to_string()];

        let found = shadowing(&store, &scopes, &path(1), &names);
        assert_eq!(found.len(), 1);
        assert!(found[0].0 == Scope::Project);
        assert_eq!(found[0].1, ["API_KEY".to_string()]);

        let found = shadowing(&store, &scopes, &path(2), &names);
        assert_eq!(found.len(), 2);
        assert!(shadowing(&store, &scopes, &path(0), &names).is_empty());
        let elsewhere = directory.path().join("other.env");
        assert!(shadowing(&store, &scopes, &elsewhere.to_string_lossy(), &names).is_empty());
    }

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
}
