use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use ggshield_secrets::{Provider, SecretStore, credential_env_vars};
use secrecy::{ExposeSecret, SecretString};

use crate::commands::shared::secret_path;
use crate::env::{validate_env_key, validate_env_value};

#[derive(clap::Args)]
pub(crate) struct Args {
    /// Secret manager to read from.
    #[arg(long, value_enum)]
    provider: Provider,
    /// Full path to a secret whose fields are injected (repeatable).
    /// Vault: <mount>/<secret path>; 1Password: <vault>/<item>;
    /// file: the project dotenv file to read (default: .env).
    /// On collisions, the value from the last path wins.
    #[arg(long = "path")]
    secrets: Vec<String>,
    /// Inject provider values even for fields whose environment variable
    /// is already set (by default the existing variable wins).
    #[arg(long)]
    no_env_override: bool,
    /// The command and its arguments, after `--`.
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

pub(crate) fn execute(args: Args) -> Result<()> {
    // The CLI handles env override itself (skip + warn below) so the user
    // sees which fields kept their existing value.
    let store = SecretStore::builder(args.provider)
        .env_override(false)
        .build()?;

    let paths = if args.secrets.is_empty() {
        // The file provider has a default path; the others do not.
        vec![secret_path(args.provider, None, None)?]
    } else {
        args.secrets.clone()
    };

    let (program, program_args) = args.command.split_first().expect("clap requires a command");

    let mut resolved = Vec::with_capacity(paths.len());
    let mut unreadable = 0;
    for path in &paths {
        let (fields, warnings) = store.get_secrets_with_warnings(path)?;
        for warning in warnings.messages() {
            eprintln!("warning: {warning}");
        }
        unreadable += warnings.unreadable.len();
        // set/import validate names on the way in, but other tools can write
        // provider fields we could not inject faithfully: a name with '=' would
        // silently define a different variable, and a NUL in either half makes
        // the spawn fail with a message naming neither the field nor the file.
        // Checked per path so the message can say where the value came from.
        for (key, value) in &fields {
            validate_env_key(key).with_context(|| format!("in {path}"))?;
            validate_env_value(key, value).with_context(|| format!("in {path}"))?;
        }
        resolved.push((path.clone(), fields));
    }
    // Reading part of a file is right for `get`, which prints what it found and
    // says what it could not. Injecting part of one is not: the child starts
    // with a variable simply absent, indistinguishable from one nobody ever set,
    // and exits 0 in a CI job where nobody reads the warnings above.
    if unreadable > 0 {
        bail!(
            "refusing to run {program}: {unreadable} value(s) named above could not be read, so \
             it would have started with them missing. Re-encrypt them on this device \
             (`ggshield secret encrypt`), remove them, or run `ggshield secret get` to see the rest"
        );
    }
    let (env, collisions) = merge_secrets(resolved);
    for collision in collisions {
        eprintln!("warning: {collision}");
    }

    let mut child = std::process::Command::new(program);
    child.args(program_args);
    // The child gets the secrets it asked for, not the credentials used to
    // fetch them: a task runner started this way must not be able to read the
    // rest of the store.
    let scrubbed = credential_env_vars();
    for name in &scrubbed {
        child.env_remove(name);
    }
    for (key, value) in &env {
        // An already-set environment variable wins by default, so the same
        // command works on a dev machine (values from the provider) and on a
        // server where the platform injects the real env vars itself.
        //
        // "Already set" has to mean "the child will actually inherit it". A
        // provider credential was just scrubbed above, so the child inherits
        // nothing — comparing against the ambient value there would skip the
        // injection *and* leave the variable unset, handing the child neither
        // token.
        let inherited =
            !scrubbed.contains(key) && std::env::var_os(key).is_some_and(|value| !value.is_empty());
        if !args.no_env_override && inherited {
            eprintln!(
                "warning: '{key}' is already set in the environment; keeping the \
                 existing value (use --no-env-override to force the provider's)"
            );
            continue;
        }
        // The whole point of `run`: the child gets the real values.
        child.env(key, value.expose_secret());
    }
    exec(child, program)
}

/// Merge resolved secrets in path order; on a field collision the later path
/// wins. Returns the merged environment and a warning per real collision,
/// naming the field and never the value.
///
/// "Real" is the whole subtlety. Every `--path` of the file provider is read
/// with the user-scope layer merged in, so each user-scope variable comes back
/// once per path — and reporting those as collisions named a file that does not
/// even contain the variable, once per extra `--path`. Since the value is the
/// same in each result, nothing is being chosen between: only a genuinely
/// different value is a collision the user needs to know about.
fn merge_secrets(
    resolved: impl IntoIterator<Item = (String, BTreeMap<String, SecretString>)>,
) -> (BTreeMap<String, SecretString>, Vec<String>) {
    let mut env: BTreeMap<String, SecretString> = BTreeMap::new();
    let mut collisions = Vec::new();
    for (path, fields) in resolved {
        for (key, value) in fields {
            let differs = env
                .get(&key)
                .is_some_and(|previous| previous.expose_secret() != value.expose_secret());
            env.insert(key.clone(), value);
            if differs {
                collisions.push(format!(
                    "field '{key}' is set to a different value by more than one secret; \
                     keeping the value from '{path}'"
                ));
            }
        }
    }
    (env, collisions)
}

/// Hand the process over to the command. On Unix this execs, so the child
/// fully replaces us: signals, exit code and streams behave as if the user had
/// run the command directly.
#[cfg(unix)]
fn exec(mut child: std::process::Command, program: &str) -> Result<()> {
    use std::os::unix::process::CommandExt;
    // exec only returns on failure.
    Err(child.exec()).with_context(|| format!("running {program}"))
}

#[cfg(not(unix))]
fn exec(mut child: std::process::Command, program: &str) -> Result<()> {
    let status = child
        .status()
        .with_context(|| format!("running {program}"))?;
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> BTreeMap<String, SecretString> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), SecretString::from(value.to_string())))
            .collect()
    }

    #[test]
    fn merge_secrets_later_path_wins_on_collision() {
        let (env, collisions) = merge_secrets([
            ("secret/a".to_string(), fields(&[("KEY", "1"), ("A", "a")])),
            ("secret/b".to_string(), fields(&[("KEY", "2"), ("B", "b")])),
        ]);
        assert_eq!(env.len(), 3);
        assert_eq!(env.get("KEY").unwrap().expose_secret(), "2");
        assert_eq!(env.get("A").unwrap().expose_secret(), "a");
        assert_eq!(env.get("B").unwrap().expose_secret(), "b");
        assert_eq!(collisions.len(), 1, "{collisions:?}");
        assert!(collisions[0].contains("'KEY'"), "{collisions:?}");
        assert!(collisions[0].contains("secret/b"), "{collisions:?}");
    }

    /// Finding 16: the user-scope layer is part of every path's result, so the
    /// same variable arriving twice with the same value is not a collision — and
    /// reporting one named a file that does not contain the variable.
    #[test]
    fn the_same_value_from_two_paths_is_not_a_collision() {
        let (env, collisions) = merge_secrets([
            (
                "one.env".to_string(),
                fields(&[("USER_WIDE", "same"), ("A", "a")]),
            ),
            (
                "two.env".to_string(),
                fields(&[("USER_WIDE", "same"), ("B", "b")]),
            ),
        ]);
        assert_eq!(env.len(), 3);
        assert_eq!(env.get("USER_WIDE").unwrap().expose_secret(), "same");
        assert!(collisions.is_empty(), "{collisions:?}");
    }
}
