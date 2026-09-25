//! The repo-scope store: one per repository, shared by every worktree.
//!
//! It lives inside the common git directory, so it can never be committed or
//! arrive via `git clone`, which is why this scope needs no trust gate. A copied
//! directory can still carry one; the shell hook checks who owns it.

use std::path::{Path, PathBuf};

use super::ownership::is_owned_by_current_user;
use super::{USER_SCOPE_DIR, USER_SCOPE_FILE};

/// The repo-scope file for the repository containing `start`, or `None` when
/// `start` is not in one.
pub(crate) fn scope_path(start: &Path) -> Option<PathBuf> {
    Some(
        common_git_dir(start)?
            .join(USER_SCOPE_DIR)
            .join(USER_SCOPE_FILE),
    )
}

/// The repository's common git directory, the one every linked worktree shares.
///
/// Parsed by hand (gitrepository-layout(5)) rather than via `git rev-parse` so
/// reads need neither a fork nor git installed.
fn common_git_dir(start: &Path) -> Option<PathBuf> {
    if let Some(common) = env_path("GIT_COMMON_DIR") {
        return Some(common);
    }
    if let Some(git_dir) = env_path("GIT_DIR") {
        return Some(resolve_common(&git_dir));
    }
    let common = resolve_common(&discover(start)?);
    is_owned_by_current_user(&common).then_some(common)
}

fn env_path(name: &str) -> Option<PathBuf> {
    let value = std::env::var_os(name)?;
    if value.is_empty() {
        return None;
    }
    Some(PathBuf::from(value))
}

/// Walk up from `start` looking for `.git`, as git itself does.
///
/// A `.git` another user owns ends the search with no repository, as git's `safe.directory`
/// check does: anyone can create `/tmp/.git` (or `C:\.git`) above someone else's directory.
fn discover(start: &Path) -> Option<PathBuf> {
    let start = std::fs::canonicalize(start).unwrap_or_else(|_| start.to_path_buf());
    for directory in start.ancestors() {
        let candidate = directory.join(".git");
        let metadata = std::fs::symlink_metadata(&candidate).ok();
        match metadata {
            Some(metadata)
                if (metadata.is_dir() || metadata.is_file())
                    && !is_owned_by_current_user(&candidate) =>
            {
                return None;
            }
            Some(metadata) if metadata.is_dir() => return Some(candidate),
            // Worktrees and submodules: a `.git` file holding `gitdir: <path>`.
            Some(metadata) if metadata.is_file() => {
                let contents = std::fs::read_to_string(&candidate).ok()?;
                let pointer = contents.strip_prefix("gitdir:")?.trim();
                if pointer.is_empty() {
                    return None;
                }
                let git_dir = directory.join(pointer);
                return is_owned_by_current_user(&git_dir).then_some(git_dir);
            }
            _ => {}
        }
    }
    None
}

/// `git_dir` itself, unless it names a linked worktree — those hold a
/// `commondir` file pointing at the repository's shared directory.
fn resolve_common(git_dir: &Path) -> PathBuf {
    let Ok(contents) = std::fs::read_to_string(git_dir.join("commondir")) else {
        return git_dir.to_path_buf();
    };
    let target = contents.trim();
    if target.is_empty() {
        return git_dir.to_path_buf();
    }
    let common = git_dir.join(target);
    std::fs::canonicalize(&common).unwrap_or(common)
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // `GIT_DIR`/`GIT_COMMON_DIR` are untested: env vars are process-global.
    fn repository(root: &Path) -> PathBuf {
        let git_dir = root.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();
        git_dir
    }

    #[test]
    fn an_ordinary_checkout_resolves_to_its_own_git_directory() {
        let temp = tempfile::tempdir().unwrap();
        let git_dir = repository(temp.path());
        let nested = temp.path().join("src/deep");
        std::fs::create_dir_all(&nested).unwrap();

        let found = common_git_dir(&nested).unwrap();
        assert_eq!(
            std::fs::canonicalize(found).unwrap(),
            std::fs::canonicalize(git_dir).unwrap()
        );
    }

    #[test]
    fn a_linked_worktree_resolves_to_the_repositorys_shared_directory() {
        let temp = tempfile::tempdir().unwrap();
        let main = temp.path().join("main");
        let git_dir = repository(&main);
        let worktree_git = git_dir.join("worktrees/feature");
        std::fs::create_dir_all(&worktree_git).unwrap();
        std::fs::write(worktree_git.join("commondir"), "../..\n").unwrap();

        let worktree = temp.path().join("feature");
        std::fs::create_dir_all(&worktree).unwrap();
        std::fs::write(
            worktree.join(".git"),
            format!("gitdir: {}\n", worktree_git.display()),
        )
        .unwrap();

        let found = common_git_dir(&worktree).unwrap();
        assert_eq!(
            std::fs::canonicalize(found).unwrap(),
            std::fs::canonicalize(git_dir).unwrap()
        );
    }

    #[test]
    fn a_submodule_keeps_its_own_store() {
        let temp = tempfile::tempdir().unwrap();
        let super_git = repository(temp.path());
        let module_git = super_git.join("modules/vendor");
        std::fs::create_dir_all(&module_git).unwrap();
        let submodule = temp.path().join("vendor");
        std::fs::create_dir_all(&submodule).unwrap();
        std::fs::write(
            submodule.join(".git"),
            format!("gitdir: {}\n", module_git.display()),
        )
        .unwrap();

        let found = common_git_dir(&submodule).unwrap();
        assert_eq!(
            std::fs::canonicalize(found).unwrap(),
            std::fs::canonicalize(module_git).unwrap()
        );
    }

    #[test]
    fn a_directory_outside_any_repository_has_no_repo_scope() {
        let temp = tempfile::tempdir().unwrap();
        assert!(scope_path(temp.path()).is_none());
    }

    #[test]
    fn the_store_sits_inside_the_git_directory() {
        let temp = tempfile::tempdir().unwrap();
        let git_dir = repository(temp.path());
        let path = scope_path(temp.path()).unwrap();
        // `discover` canonicalizes (/var -> /private/var on macOS).
        assert_eq!(
            path,
            std::fs::canonicalize(git_dir)
                .unwrap()
                .join("gitguardian")
                .join("secrets.env")
        );
    }

    /// The pointed-to directory is checked too: `/` belongs to root, not to this user.
    #[cfg(unix)]
    #[test]
    fn a_gitdir_owned_by_another_user_is_not_a_repository() {
        // SAFETY: `geteuid` has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join(".git"), "gitdir: /\n").unwrap();
        assert!(scope_path(temp.path()).is_none());
    }

    /// A worktree whose repository directory another user owns is not trusted either.
    #[cfg(unix)]
    #[test]
    fn a_commondir_owned_by_another_user_is_not_a_repository() {
        // SAFETY: `geteuid` has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let git_dir = repository(temp.path());
        std::fs::write(git_dir.join("commondir"), "/\n").unwrap();
        assert!(scope_path(temp.path()).is_none());
    }

    #[test]
    fn an_empty_gitdir_pointer_is_not_a_repository() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join(".git"), "gitdir:\n").unwrap();
        assert!(scope_path(temp.path()).is_none());
    }
}
