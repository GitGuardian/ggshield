use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use ggshield_secrets::{Provider, SecretStore, credential_env_vars};
use secrecy::{ExposeSecret, SecretString};

use crate::commands::activate::is_shell_control_var;
use crate::commands::shared::{Scope, ensure_explicit_path_exists, resolve_provider, secret_path};
use crate::env::{validate_env_key, validate_env_value};

#[derive(clap::Args)]
pub(crate) struct Args {
    /// Secret manager to read from.
    /// Default: `secret.provider` in .gitguardian.yaml, else file.
    #[arg(long, value_enum)]
    provider: Option<Provider>,
    /// Full path to a secret whose fields are injected (repeatable).
    /// Vault: <mount>/<secret path>;
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
    let provider = resolve_provider(args.provider)?;
    // Env override is handled below so the user is warned which fields kept their value.
    let store = SecretStore::builder(provider)
        .env_override(false)
        .project_path_is_default(args.secrets.is_empty())
        .build()?;

    let paths = if args.secrets.is_empty() {
        vec![secret_path(provider, None, None)?]
    } else {
        for path in &args.secrets {
            ensure_explicit_path_exists(provider, path)?;
        }
        args.secrets.clone()
    };

    let (program, program_args) = args.command.split_first().expect("clap requires a command");

    let mut resolved = Vec::with_capacity(paths.len());
    let mut unreadable = 0;
    for path in &paths {
        let (mut fields, warnings) = store.get_secrets_with_warnings(path)?;
        for warning in warnings.messages() {
            eprintln!("warning: {warning}");
        }
        unreadable += warnings.unreadable.len();
        if provider == Provider::File && args.secrets.is_empty() {
            let refused = drop_control_vars(&mut fields, &store.field_scopes(path)?);
            if !refused.is_empty() {
                eprintln!(
                    "warning: refused to inject {} from {path} that {} how programs run: {}. \
                     Pass --path {path} to inject {} anyway",
                    variable_count(refused.len()),
                    if refused.len() == 1 {
                        "changes"
                    } else {
                        "change"
                    },
                    refused.join(", "),
                    if refused.len() == 1 { "it" } else { "them" },
                );
            }
        }
        // Other tools can write fields we cannot inject faithfully ('=' in a name,
        // a NUL); checked per path so the error names the file.
        for (key, value) in &fields {
            validate_env_key(key).with_context(|| format!("in {path}"))?;
            validate_env_value(key, value).with_context(|| format!("in {path}"))?;
        }
        resolved.push((path.clone(), fields));
    }
    // Unlike `get`, never inject a partial file: the child would silently start
    // without the variable and exit 0 in CI where nobody reads warnings.
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
    // Scrub provider credentials so the child cannot read the rest of the store.
    let scrubbed = credential_env_vars();
    for name in &scrubbed {
        child.env_remove(name);
    }
    for (key, value) in &env {
        // "Already set" must mean the child inherits it: a scrubbed credential is
        // not inherited, so skipping it would hand the child neither token.
        let inherited =
            !scrubbed.contains(key) && std::env::var_os(key).is_some_and(|value| !value.is_empty());
        if !args.no_env_override && inherited {
            eprintln!(
                "warning: '{key}' is already set in the environment; keeping the \
                 existing value (use --no-env-override to force the provider's)"
            );
            continue;
        }
        child.env(key, value.expose_secret());
    }
    exec(child, program)
}

/// A `.env` nobody named is not consent: a cloned repository could set `LD_PRELOAD`. Only the
/// project layer; the other scopes are the user's own.
fn drop_control_vars(
    fields: &mut BTreeMap<String, SecretString>,
    scopes: &BTreeMap<String, String>,
) -> Vec<String> {
    let project = Scope::Project.to_string();
    let refused = fields
        .keys()
        .filter(|key| is_shell_control_var(key) && scopes.get(*key) == Some(&project))
        .cloned()
        .collect::<Vec<_>>();
    for key in &refused {
        fields.remove(key);
    }
    refused
}

fn variable_count(count: usize) -> String {
    match count {
        1 => "1 variable".to_string(),
        count => format!("{count} variables"),
    }
}

/// Later paths win. Only a differing value is a collision: every file-provider
/// path includes the user-scope layer, so identical repeats are expected.
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

/// On Unix, exec so signals, exit code and streams behave as if run directly.
#[cfg(unix)]
fn exec(mut child: std::process::Command, program: &str) -> ! {
    use std::os::unix::process::CommandExt;
    let error = child.exec();
    cannot_start(program, &error)
}

#[cfg(not(unix))]
fn exec(mut child: std::process::Command, program: &str) -> ! {
    match child.status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(error) => cannot_start(program, &error),
    }
}

/// Exits as a shell would, so a caller can tell this from the program's own failure.
fn cannot_start(program: &str, error: &std::io::Error) -> ! {
    eprintln!("Error: cannot run {program}: {error}");
    std::process::exit(start_failure_code(error))
}

fn start_failure_code(error: &std::io::Error) -> i32 {
    match error.kind() {
        std::io::ErrorKind::NotFound => 127,
        _ => 126,
    }
}

#[cfg(test)]
// A failed unwrap is the assertion failing; the lint targets shipped code.
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

    #[test]
    fn a_program_that_cannot_start_exits_like_a_shell() {
        use std::io::{Error, ErrorKind};
        assert_eq!(start_failure_code(&Error::from(ErrorKind::NotFound)), 127);
        assert_eq!(
            start_failure_code(&Error::from(ErrorKind::PermissionDenied)),
            126
        );
    }

    #[test]
    fn control_vars_from_the_default_env_are_dropped() {
        let mut env = fields(&[
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("NODE_OPTIONS", "--require evil"),
            ("API_KEY", "k"),
        ]);
        let scopes = [
            ("LD_PRELOAD", "project"),
            ("NODE_OPTIONS", "global"),
            ("API_KEY", "project"),
        ]
        .into_iter()
        .map(|(key, scope)| (key.to_string(), scope.to_string()))
        .collect();
        let refused = drop_control_vars(&mut env, &scopes);
        assert_eq!(refused, ["LD_PRELOAD".to_string()]);
        assert!(!env.contains_key("LD_PRELOAD"));
        assert!(
            env.contains_key("NODE_OPTIONS"),
            "the user's own scope is consent"
        );
        assert!(env.contains_key("API_KEY"));
    }

    /// The same value arriving from two paths is not a collision.
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
