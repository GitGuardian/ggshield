use std::collections::BTreeSet;
use std::io::{IsTerminal, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use ggshield_secrets::{
    DEFAULT_PROJECT_PATH, Provider, SecretError, SecretStore, repo_scope_path, system_scope_path,
    user_scope_path,
};

/// Which file a `file`-provider value is written to, git-config style.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    System,
    Global,
    Local,
    Project,
}

/// The scope flags, spelled the way `git config` spells them.
#[derive(clap::Args)]
#[group(multiple = false)]
pub(crate) struct ScopeArgs {
    /// Use this machine's file, shared by every user of it (file provider).
    /// Read-only in practice: writing it needs the privileges /etc demands.
    #[arg(long)]
    system: bool,
    /// Use this user's file, shared by every project (file provider).
    #[arg(long)]
    global: bool,
    /// Use the repository's file, shared by every worktree of it (file
    /// provider). Lives in the git directory, so it is never committed.
    #[arg(long)]
    local: bool,
    /// Use the checkout's own .env (file provider).
    #[arg(long)]
    project: bool,
}

impl ScopeArgs {
    pub(crate) fn get(&self) -> Option<Scope> {
        if self.system {
            Some(Scope::System)
        } else if self.global {
            Some(Scope::Global)
        } else if self.local {
            Some(Scope::Local)
        } else if self.project {
            Some(Scope::Project)
        } else {
            None
        }
    }
}

static CONFIG_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// `ggshield --config-path`: the only config file read, as in Python.
pub(crate) fn set_config_path(path: std::path::PathBuf) {
    let _ = CONFIG_PATH.set(path);
}

/// `--provider`, else `secret.provider` in `.gitguardian.yaml`, else the file provider.
pub(crate) fn resolve_provider(flag: Option<Provider>) -> Result<Provider> {
    if let Some(provider) = flag {
        return Ok(provider);
    }
    let configured =
        ggshield_config::user_config::secret_provider(CONFIG_PATH.get().map(|path| path.as_path()))
            .map_err(anyhow::Error::msg)?;
    match configured.as_deref() {
        None => Ok(Provider::File),
        Some(name) => provider_named(name),
    }
}

fn provider_named(name: &str) -> Result<Provider> {
    Provider::ALL
        .iter()
        .copied()
        .find(|provider| provider.as_str() == name)
        .ok_or_else(|| {
            let known: Vec<&str> = Provider::ALL
                .iter()
                .map(|provider| provider.as_str())
                .collect();
            anyhow::anyhow!(
                "secret.provider in .gitguardian.yaml is '{name}'; expected one of: {}",
                known.join(", ")
            )
        })
}

pub(crate) fn secret_path(
    provider: Provider,
    path: Option<String>,
    scope: Option<Scope>,
) -> Result<String> {
    resolve_path(provider, path, scope, Default_::Project)
}

/// A read of a `--path` that names no file must fail: the other scopes would
/// otherwise be read in its place, and a typo would go unnoticed.
pub(crate) fn ensure_explicit_path_exists(provider: Provider, path: &str) -> Result<()> {
    if provider != Provider::File {
        return Ok(());
    }
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(SecretError::SecretNotFound {
                path: path.to_string(),
            }
            .into())
        }
        _ => Ok(()),
    }
}

/// Like [`secret_path`], but defaults to the repository's file so worktrees
/// share values instead of each needing its own `.env`.
pub(crate) fn write_path(
    provider: Provider,
    path: Option<String>,
    scope: Option<Scope>,
) -> Result<String> {
    resolve_path(provider, path, scope, Default_::Repo)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Default_ {
    Project,
    Repo,
}

fn resolve_path(
    provider: Provider,
    path: Option<String>,
    scope: Option<Scope>,
    default: Default_,
) -> Result<String> {
    if provider != Provider::File {
        if scope.is_some() {
            bail!("--system, --global, --local and --project only apply to the file provider");
        }
        return path.ok_or_else(|| anyhow::anyhow!("--path is required for provider '{provider}'"));
    }
    match (scope, path) {
        (Some(Scope::System), Some(_)) => bail!("--system and --path cannot be combined"),
        (Some(Scope::System), None) => require_utf8_path(
            system_scope_path()
                .ok_or_else(|| anyhow::anyhow!("this platform has no system scope"))?,
        ),
        (Some(Scope::Global), Some(_)) => bail!("--global and --path cannot be combined"),
        (Some(Scope::Global), None) => require_utf8_path(user_scope_path()?),
        (Some(Scope::Local), Some(_)) => bail!("--local and --path cannot be combined"),
        (Some(Scope::Local), None) => require_utf8_path(explicit_repo_path()?),
        (_, Some(path)) => Ok(path),
        (Some(Scope::Project), None) => Ok(DEFAULT_PROJECT_PATH.to_string()),
        (None, None) => match default {
            Default_::Project => Ok(DEFAULT_PROJECT_PATH.to_string()),
            Default_::Repo => match repo_path() {
                Some(path) => require_utf8_path(path),
                None => Ok(DEFAULT_PROJECT_PATH.to_string()),
            },
        },
    }
}

fn repo_path() -> Option<std::path::PathBuf> {
    repo_scope_path(Path::new("."))
}

fn explicit_repo_path() -> Result<std::path::PathBuf> {
    repo_path().ok_or_else(|| {
        anyhow::anyhow!(
            "--local needs a git repository, and this directory is not in one. Use --project (the \
             default here) or --path to name a file"
        )
    })
}

/// Refused rather than `to_string_lossy`: a mangled path is a different file
/// from the one later reads look for.
fn require_utf8_path(path: std::path::PathBuf) -> Result<String> {
    path.into_os_string().into_string().map_err(|path| {
        anyhow::anyhow!(
            "the scope file's path is not valid UTF-8 ({}), and this command cannot name it \
             without changing it. Pass --path with a UTF-8 path, or set $XDG_CONFIG_HOME (on \
             macOS, $HOME) to one",
            Path::new(&path).display()
        )
    })
}

/// Returns the names shown so the write can detect a file changed since: the
/// lock cannot be held across a prompt.
pub(crate) fn confirm_existing_fields(
    store: &SecretStore,
    path: &str,
    keys: &[String],
) -> Result<BTreeSet<String>> {
    let existing = store.field_names(path)?;
    let overlaps = keys
        .iter()
        .filter(|key| existing.contains(*key))
        .cloned()
        .collect::<BTreeSet<_>>();
    if overlaps.is_empty() {
        return Ok(overlaps);
    }

    eprintln!(
        "{path} already contains {}. {} will be overwritten.",
        overlaps.iter().cloned().collect::<Vec<_>>().join(", "),
        field_count(overlaps.len())
    );
    confirm()?;
    Ok(overlaps)
}

pub(crate) fn field_count(count: usize) -> String {
    match count {
        1 => "1 field".to_string(),
        count => format!("{count} fields"),
    }
}

pub(crate) fn confirm() -> Result<()> {
    // stdin may already be consumed (piped into `import`), giving a misleading "aborted".
    if !std::io::stdin().is_terminal() {
        bail!(
            "cannot ask for confirmation: stdin is not a terminal (pass --yes to skip the prompt)"
        );
    }
    eprint!("Continue? [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    match answer.trim() {
        "y" | "Y" | "yes" | "YES" | "Yes" => Ok(()),
        _ => bail!("aborted"),
    }
}

pub(crate) fn prompt_secret(key: &str, expose: bool, allow_empty: bool) -> Result<String> {
    let value = read_secret(key, expose)?;
    if value.is_empty() && !allow_empty {
        bail!(
            "no value was given for '{key}'. Storing an empty value would overwrite whatever \
             is there with nothing, and an overwritten encrypted value cannot be recovered; \
             pass --allow-empty if an empty value is really what you want"
        );
    }
    Ok(value)
}

fn read_secret(key: &str, expose: bool) -> Result<String> {
    eprint!("{key}: ");
    std::io::stderr().flush()?;
    // rpassword reads /dev/tty, which is not where piped input is.
    if expose || !std::io::stdin().is_terminal() {
        let mut value = String::new();
        // EOF (`Ok(0)`) is not an empty line; treating it as one would overwrite
        // stored values with "".
        if std::io::stdin().read_line(&mut value)? == 0 {
            bail!(
                "no value for '{key}': stdin is at end of file. Values are read one line per \
                 field, in the order the fields are named, so a closed or already-consumed \
                 stdin — or fewer piped lines than fields — leaves fields with no value"
            );
        }
        Ok(value.trim_end_matches(['\r', '\n']).to_string())
    } else {
        rpassword::read_password().context("reading secret input")
    }
}

#[cfg(test)]
// A failed unwrap is the assertion failing; the lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn field_count_uses_singular_for_one() {
        assert_eq!(field_count(1), "1 field");
        assert_eq!(field_count(2), "2 fields");
    }

    #[test]
    fn the_file_provider_defaults_to_the_project_dotenv() {
        assert_eq!(
            secret_path(Provider::File, None, None).unwrap(),
            DEFAULT_PROJECT_PATH
        );
        assert_eq!(
            secret_path(Provider::File, Some("other.env".to_string()), None).unwrap(),
            "other.env"
        );
        assert!(
            secret_path(Provider::File, None, Some(Scope::Global))
                .unwrap()
                .ends_with("secrets.env")
        );
    }

    #[test]
    fn other_providers_need_an_explicit_path_and_take_no_scope() {
        let error = secret_path(Provider::Vault, None, None).unwrap_err();
        assert!(error.to_string().contains("--path is required"));
        let error = secret_path(
            Provider::Vault,
            Some("a/b".to_string()),
            Some(Scope::Global),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("only apply to the file provider")
        );
    }

    #[test]
    fn global_and_path_cannot_be_combined() {
        let error = secret_path(
            Provider::File,
            Some(".env".to_string()),
            Some(Scope::Global),
        )
        .unwrap_err();
        assert!(error.to_string().contains("cannot be combined"));
    }

    #[cfg(unix)]
    #[test]
    fn a_user_scope_path_that_is_not_utf8_is_refused_rather_than_mangled() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let mangled = std::path::PathBuf::from(OsString::from_vec(
            b"/home/us\xffer/.config/gitguardian/secrets.env".to_vec(),
        ));
        let error = require_utf8_path(mangled).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("not valid UTF-8"), "{message}");
        assert!(message.contains("secrets.env"), "{message}");

        assert_eq!(
            require_utf8_path(std::path::PathBuf::from("/home/user/secrets.env")).unwrap(),
            "/home/user/secrets.env"
        );
    }
}
