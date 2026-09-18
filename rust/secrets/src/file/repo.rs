//! Where the repo-scope file lives: one store per repository, shared by every
//! worktree of it.
//!
//! A worktree per branch is the normal way to work on this repository, and a
//! project-scope `.env` has to be recreated in each one. The values are the
//! same every time, so the file that holds them belongs to the repository, not
//! to the checkout.
//!
//! It lives *inside* the git directory rather than beside it. A
//! `.gitguardian/` at the top of the working tree would be one `git add -A`
//! away from being committed, and `git clone` never transfers anything under
//! `.git/` — which is also why this scope needs no trust gate, unlike a `.env`
//! that can arrive with a repository somebody else wrote.
//!
//! "The git directory" here means the *common* one: a linked worktree's own
//! git directory is `<main>/.git/worktrees/<name>`, and using that would put a
//! separate store in every worktree, which is the problem this scope exists to
//! solve.

use std::path::{Path, PathBuf};

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
/// Deliberately not `git rev-parse --git-common-dir`: that would make every
/// read of a dotenv file fork a process, and require git to be installed to
/// read a file we can find ourselves. The formats parsed here (a `gitdir:`
/// pointer file, a `commondir` file) are the documented ones in gitrepository-
/// layout(5).
fn common_git_dir(start: &Path) -> Option<PathBuf> {
    // Honoured for the same reason git honours them: a caller that has already
    // decided which repository this is must win over anything found by walking.
    if let Some(common) = env_path("GIT_COMMON_DIR") {
        return Some(common);
    }
    let git_dir = match env_path("GIT_DIR") {
        Some(git_dir) => git_dir,
        None => discover(start)?,
    };
    Some(resolve_common(&git_dir))
}

fn env_path(name: &str) -> Option<PathBuf> {
    let value = std::env::var_os(name)?;
    if value.is_empty() {
        return None;
    }
    Some(PathBuf::from(value))
}

/// Walk up from `start` looking for `.git`, as git itself does.
fn discover(start: &Path) -> Option<PathBuf> {
    let start = std::fs::canonicalize(start).unwrap_or_else(|_| start.to_path_buf());
    for directory in start.ancestors() {
        let candidate = directory.join(".git");
        let metadata = std::fs::symlink_metadata(&candidate).ok();
        match metadata {
            // The ordinary case: `.git` is the git directory.
            Some(metadata) if metadata.is_dir() => return Some(candidate),
            // A linked worktree (and a submodule) has a `.git` *file* holding
            // `gitdir: <path>`, relative to the file's own directory.
            Some(metadata) if metadata.is_file() => {
                let contents = std::fs::read_to_string(&candidate).ok()?;
                let pointer = contents.strip_prefix("gitdir:")?.trim();
                if pointer.is_empty() {
                    return None;
                }
                return Some(directory.join(pointer));
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
    // `commondir` is usually the relative `../..`; keep the path readable in
    // error messages rather than leaving those components in it.
    std::fs::canonicalize(&common).unwrap_or(common)
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing, which is what a test is
// for; the workspace lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The env-var branches (`GIT_DIR`, `GIT_COMMON_DIR`) are deliberately not
    /// covered here: setting them is process-global, and `cargo test` runs
    /// these as threads in one process, so a test that set them would change
    /// what every other test in this file discovers.
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
        // The layout `git worktree add` writes: the worktree's `.git` is a file
        // pointing into the main repository, and that directory names the
        // common one. Without following `commondir` every worktree would get a
        // store of its own, which is the whole point of this scope.
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
        // A submodule's `.git` is a pointer too, but into `.git/modules/<name>`,
        // which carries no `commondir`: it is a repository in its own right and
        // its secrets are not the superproject's.
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
        // `discover` canonicalizes as it walks (/var -> /private/var on macOS),
        // so compare canonical paths rather than the tempdir's own spelling.
        assert_eq!(
            path,
            std::fs::canonicalize(git_dir)
                .unwrap()
                .join("gitguardian")
                .join("secrets.env")
        );
    }

    #[test]
    fn an_empty_gitdir_pointer_is_not_a_repository() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join(".git"), "gitdir:\n").unwrap();
        assert!(scope_path(temp.path()).is_none());
    }
}
