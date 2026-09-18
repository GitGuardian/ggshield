use std::collections::BTreeSet;
use std::io::{IsTerminal, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use ggshield_secrets::{
    DEFAULT_PROJECT_PATH, Provider, SecretStore, repo_scope_path, system_scope_path,
    user_scope_path,
};

/// Which file a `file`-provider value is written to, git-config style.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Scope {
    /// This machine's file, shared by every user of it. Read-only in practice:
    /// writing it needs the privileges /etc demands.
    System,
    /// This machine's user file, shared by every project.
    User,
    /// The repository's file, shared by every worktree of it. Lives in the git
    /// directory, so it is never committed and never arrives with a clone.
    Repo,
    /// The checkout's own file.
    Project,
}

/// The file or secret path a command should act on.
///
/// Only the `file` provider has a default path and scopes; for the others the
/// path names a secret in a remote store, and there is nothing to default to.
pub(crate) fn secret_path(
    provider: Provider,
    path: Option<String>,
    scope: Option<Scope>,
) -> Result<String> {
    resolve_path(provider, path, scope, Default_::Project)
}

/// The file a *writing* command should act on.
///
/// Same rules as [`secret_path`], except that with neither `--scope` nor
/// `--path` it targets the repository's file when there is one. Writing the
/// checkout's `.env` by default is what makes every worktree of a repository
/// need its own copy of the same values, which is the duplication the repo
/// scope exists to end; `--scope project` still names the checkout's file when
/// a value really is local to it.
pub(crate) fn write_path(
    provider: Provider,
    path: Option<String>,
    scope: Option<Scope>,
) -> Result<String> {
    resolve_path(provider, path, scope, Default_::Repo)
}

/// Which file an unqualified command means.
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
            bail!("--scope only applies to the file provider");
        }
        return path.ok_or_else(|| anyhow::anyhow!("--path is required for provider '{provider}'"));
    }
    match (scope, path) {
        (Some(Scope::System), Some(_)) => bail!("--scope system and --path cannot be combined"),
        (Some(Scope::System), None) => require_utf8_path(
            system_scope_path()
                .ok_or_else(|| anyhow::anyhow!("this platform has no system scope"))?,
        ),
        (Some(Scope::User), Some(_)) => bail!("--scope user and --path cannot be combined"),
        (Some(Scope::User), None) => require_utf8_path(user_scope_path()?),
        (Some(Scope::Repo), Some(_)) => bail!("--scope repo and --path cannot be combined"),
        (Some(Scope::Repo), None) => require_utf8_path(explicit_repo_path()?),
        (_, Some(path)) => Ok(path),
        (Some(Scope::Project), None) => Ok(DEFAULT_PROJECT_PATH.to_string()),
        (None, None) => match default {
            Default_::Project => Ok(DEFAULT_PROJECT_PATH.to_string()),
            // Outside a repository there is nothing to share a store with, so
            // this is the project file and no explanation is owed.
            Default_::Repo => match repo_path() {
                Some(path) => require_utf8_path(path),
                None => Ok(DEFAULT_PROJECT_PATH.to_string()),
            },
        },
    }
}

/// The repo-scope file for the current directory.
fn repo_path() -> Option<std::path::PathBuf> {
    repo_scope_path(Path::new("."))
}

/// The same, for `--scope repo`, where not being in a repository is an error
/// rather than a reason to pick another file.
fn explicit_repo_path() -> Result<std::path::PathBuf> {
    repo_path().ok_or_else(|| {
        anyhow::anyhow!(
            "--scope repo needs a git repository, and this directory is not in one. Use --scope \
             project (the default here) or --path to name a file"
        )
    })
}

/// A platform path as a `String`, refused rather than converted lossily.
///
/// Every path this CLI passes around is a `String`, and `to_string_lossy` turns
/// a non-UTF-8 byte in `$HOME` into a replacement character — a *different*
/// pathname from the one the core crate's byte-preserving `PathBuf` later looks
/// for. `set --scope user` wrote to the mangled name, reported success, and the
/// value could never be read back.
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

/// Warn about the fields a write would overwrite and ask before it happens.
///
/// Returns the names that were shown to the user, so the write itself can check
/// that the file still looks like the one they answered about: this read is not
/// under the write lock, and it cannot be — an unanswered prompt would hold the
/// lock for as long as the terminal sits there.
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
    // Without a terminal there is nobody to answer — and stdin may already
    // be consumed (a dotenv piped into `import`), so reading would see EOF
    // and abort with a misleading plain "aborted".
    if !std::io::stdin().is_terminal() {
        bail!(
            "cannot ask for confirmation: stdin is not a terminal (pass --yes to skip the prompt)"
        );
    }
    // Prompts go to stderr like every other message, so redirecting or
    // piping a command's stdout never captures them.
    eprint!("Continue? [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    match answer.trim() {
        "y" | "Y" | "yes" | "YES" | "Yes" => Ok(()),
        _ => bail!("aborted"),
    }
}

/// Read one secret value for `key`.
///
/// An empty value is refused unless `allow_empty`: the only thing `set` can do
/// with one is overwrite whatever is stored under that name with nothing, and
/// for an encrypted value there is no way to get it back.
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
    // Piped input has no typing to hide, and rpassword would go looking for
    // /dev/tty — which either is not there or is not where the value is.
    if expose || !std::io::stdin().is_terminal() {
        let mut value = String::new();
        // `read_line` reports end of file as `Ok(0)`, which is not the same
        // thing as reading an empty line. Conflating the two is how
        // `set --yes API_KEY < /dev/null` came to report success while
        // replacing good ciphertext with an encryption of the empty string —
        // and how piping fewer lines than fields silently emptied the rest.
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
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
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
            secret_path(Provider::File, None, Some(Scope::User))
                .unwrap()
                .ends_with("secrets.env")
        );
    }

    #[test]
    fn other_providers_need_an_explicit_path_and_take_no_scope() {
        let error = secret_path(Provider::Vault, None, None).unwrap_err();
        assert!(error.to_string().contains("--path is required"));
        let error =
            secret_path(Provider::Vault, Some("a/b".to_string()), Some(Scope::User)).unwrap_err();
        assert!(error.to_string().contains("--scope only applies"));
    }

    #[test]
    fn scope_user_and_path_cannot_be_combined() {
        let error =
            secret_path(Provider::File, Some(".env".to_string()), Some(Scope::User)).unwrap_err();
        assert!(error.to_string().contains("cannot be combined"));
    }

    /// Finding 23: `--scope user` used to run the real platform path through
    /// `to_string_lossy`, so a non-UTF-8 byte in `$HOME` — legal on Unix —
    /// silently became a replacement character. The write went to the mangled
    /// pathname and every later read looked for the real one.
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

        // A path that is valid UTF-8 comes through untouched.
        assert_eq!(
            require_utf8_path(std::path::PathBuf::from("/home/user/secrets.env")).unwrap(),
            "/home/user/secrets.env"
        );
    }
}
