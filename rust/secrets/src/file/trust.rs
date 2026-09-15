//! Which dotenv files this user has agreed to load automatically.
//!
//! Only `activate`'s shell hook consults this. `get`, `run` and `encrypt` name
//! a file on the command line, so the invocation *is* the consent; the hook
//! loads whatever directory you happen to walk into, which is not the same
//! thing at all. A `.env` in a repository you just cloned would otherwise
//! reach your shell before you had read it.
//!
//! # Why the content is hashed, not just the path
//!
//! Trusting a path and stopping there would mean approving a file once and
//! inheriting every later edit — including a line someone else pushed. An entry
//! is therefore `(canonical path, SHA-256 of the contents)`, so any change to
//! the file revokes trust until the user looks again. That is `direnv`'s
//! behaviour and the reason its `allow` prompt reappears after every edit.
//!
//! The hash must be cryptographic. Trust is *decided* by comparing it, so a
//! cheap hash would let anyone who can write the file craft a collision and be
//! trusted without asking.
//!
//! # Why per-user and not per-repository
//!
//! The store lives beside the user's other gitguardian state, never in the
//! project. A committed trust file would be written by whoever wrote the `.env`
//! it is vouching for, which is exactly the party the gate exists to stop.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use super::atomic;

/// File holding this user's approvals, beside `secrets.env`.
const TRUST_FILE: &str = "trusted";

/// One approval: the file, and the contents that were approved.
struct Entry {
    digest: String,
    path: PathBuf,
}

/// Whether `path`'s current contents are approved for automatic loading.
///
/// A file that cannot be read, or a store that cannot be read, is *not*
/// trusted: this gate fails closed, like the keyring does.
pub fn is_trusted(path: &Path) -> Result<bool> {
    let Some(digest) = digest_of(path)? else {
        return Ok(false);
    };
    let canonical = canonical(path);
    Ok(load()?
        .iter()
        .any(|entry| entry.path == canonical && entry.digest == digest))
}

/// Approve `path`'s current contents, returning false if it was already
/// approved unchanged.
pub fn trust(path: &Path) -> Result<bool> {
    let digest = digest_of(path)?.with_context(|| {
        format!(
            "{} does not exist, so there is nothing to trust",
            path.display()
        )
    })?;
    let canonical = canonical(path);

    let mut entries = load()?;
    if entries
        .iter()
        .any(|entry| entry.path == canonical && entry.digest == digest)
    {
        return Ok(false);
    }
    // One entry per file: approving new contents replaces the old approval
    // rather than accumulating, so an old digest can never come back.
    entries.retain(|entry| entry.path != canonical);
    entries.push(Entry {
        digest,
        path: canonical,
    });
    save(&entries)?;
    Ok(true)
}

/// Withdraw approval for `path`, returning whether there was one.
pub fn untrust(path: &Path) -> Result<bool> {
    let canonical = canonical(path);
    let mut entries = load()?;
    let before = entries.len();
    entries.retain(|entry| entry.path != canonical);
    if entries.len() == before {
        return Ok(false);
    }
    save(&entries)?;
    Ok(true)
}

/// Every approval on record, for `gitguardian trust --list`.
pub fn trusted_paths() -> Result<Vec<PathBuf>> {
    Ok(load()?.into_iter().map(|entry| entry.path).collect())
}

/// Where the store lives.
pub fn trust_path() -> Result<PathBuf> {
    Ok(super::user_scope_path()?.with_file_name(TRUST_FILE))
}

/// SHA-256 of `path`'s contents, or `None` when there is no such file.
fn digest_of(path: &Path) -> Result<Option<String>> {
    // Through the same reader the provider uses, so a symlink or a device node
    // is refused here exactly as it is there — the digest must describe the
    // bytes that would actually be loaded.
    let Some(contents) = atomic::read_to_string(path)? else {
        return Ok(None);
    };
    let mut hasher = Sha256::new();
    hasher.update(contents.as_bytes());
    Ok(Some(
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    ))
}

/// The path as stored: resolved when possible, so `./env` and an absolute path
/// to the same file are one entry.
///
/// Falls back to the path as given when it cannot be resolved, rather than
/// failing — an unresolvable path simply will not match a stored entry, which
/// is the safe direction.
fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Read the store. A missing store is an empty one.
///
/// Line-oriented rather than TOML: two columns need no parser, and a line this
/// code cannot read is skipped rather than fatal, so a store damaged by a disk
/// full or an editor cannot lock the user out of their own shell — the worst it
/// costs is re-running `trust`.
fn load() -> Result<Vec<Entry>> {
    let path = trust_path()?;
    let Some(contents) = atomic::read_to_string(&path)? else {
        return Ok(Vec::new());
    };
    Ok(contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (digest, path) = line.split_once(char::is_whitespace)?;
            if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            Some(Entry {
                digest: digest.to_string(),
                path: PathBuf::from(path.trim_start()),
            })
        })
        .collect())
}

fn save(entries: &[Entry]) -> Result<()> {
    let path = trust_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut out = String::from(
        "# Dotenv files this user has approved for `gitguardian activate`.\n\
         # <sha256 of the contents> <path>. Editing the file revokes its approval.\n",
    );
    for entry in entries {
        out.push_str(&entry.digest);
        out.push(' ');
        out.push_str(&entry.path.to_string_lossy());
        out.push('\n');
    }
    // Same all-or-nothing write as the dotenv files: a half-written store would
    // silently un-trust an arbitrary suffix of the list.
    atomic::replace_bytes(&path, out.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing, which is what a
// test is for; the workspace lint targets shipped code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The store's location comes from the environment, so each test gets its
    /// own home. Serialised because they all mutate process-wide state.
    fn with_home<T>(body: impl FnOnce(&Path) -> T) -> T {
        static GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _lock = GUARD.lock().unwrap_or_else(|error| error.into_inner());
        let home = tempfile::tempdir().unwrap();
        let previous: Vec<(&str, Option<std::ffi::OsString>)> =
            ["HOME", "XDG_CONFIG_HOME", "USERPROFILE", "APPDATA"]
                .iter()
                .map(|key| (*key, std::env::var_os(key)))
                .collect();
        // SAFETY: single-threaded within the guard, and only this test's vars.
        unsafe {
            std::env::set_var("HOME", home.path());
            std::env::set_var("XDG_CONFIG_HOME", home.path().join(".config"));
            std::env::set_var("USERPROFILE", home.path());
            std::env::set_var("APPDATA", home.path().join("AppData/Roaming"));
        }
        let result = body(home.path());
        unsafe {
            for (key, value) in previous {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
        result
    }

    #[test]
    fn an_unknown_file_is_not_trusted() {
        with_home(|home| {
            let env = home.join("project.env");
            std::fs::write(&env, "A=1\n").unwrap();
            assert!(!is_trusted(&env).unwrap());
        });
    }

    #[test]
    fn trusting_then_editing_revokes_it() {
        with_home(|home| {
            let env = home.join("project.env");
            std::fs::write(&env, "A=1\n").unwrap();
            assert!(trust(&env).unwrap());
            assert!(is_trusted(&env).unwrap());

            // The whole point of hashing the contents: an edge someone else
            // pushed does not inherit yesterday's approval.
            std::fs::write(&env, "A=1\nPROMPT_COMMAND=touch /tmp/x\n").unwrap();
            assert!(!is_trusted(&env).unwrap());

            // And re-approving the new contents does not leave the old digest
            // behind, so reverting the file does not silently re-trust it.
            assert!(trust(&env).unwrap());
            std::fs::write(&env, "A=1\n").unwrap();
            assert!(!is_trusted(&env).unwrap());
        });
    }

    #[test]
    fn trusting_twice_reports_no_change() {
        with_home(|home| {
            let env = home.join("project.env");
            std::fs::write(&env, "A=1\n").unwrap();
            assert!(trust(&env).unwrap());
            assert!(!trust(&env).unwrap());
            assert_eq!(trusted_paths().unwrap().len(), 1);
        });
    }

    #[test]
    fn untrust_reports_whether_there_was_an_approval() {
        with_home(|home| {
            let env = home.join("project.env");
            std::fs::write(&env, "A=1\n").unwrap();
            assert!(!untrust(&env).unwrap());
            trust(&env).unwrap();
            assert!(untrust(&env).unwrap());
            assert!(!is_trusted(&env).unwrap());
        });
    }

    #[test]
    fn a_missing_file_cannot_be_trusted() {
        with_home(|home| {
            let env = home.join("absent.env");
            assert!(!is_trusted(&env).unwrap());
            assert!(trust(&env).is_err());
        });
    }

    #[test]
    fn a_damaged_store_is_skipped_rather_than_fatal() {
        with_home(|home| {
            let env = home.join("project.env");
            std::fs::write(&env, "A=1\n").unwrap();
            trust(&env).unwrap();

            // A truncated digest, a non-hex digest, and a line with no path.
            let store = trust_path().unwrap();
            let good = std::fs::read_to_string(&store).unwrap();
            std::fs::write(
                &store,
                format!(
                    "{good}deadbeef /short/digest\nzz{} /not/hex\nnopath\n",
                    "z".repeat(62)
                ),
            )
            .unwrap();

            // The real entry still reads, and nothing errors.
            assert!(is_trusted(&env).unwrap());
            assert_eq!(trusted_paths().unwrap().len(), 1);
        });
    }

    #[test]
    fn the_same_file_by_two_paths_is_one_entry() {
        with_home(|home| {
            let env = home.join("project.env");
            std::fs::write(&env, "A=1\n").unwrap();
            trust(&env).unwrap();
            // A path with a redundant component resolves to the same file.
            let indirect = home.join(".").join("project.env");
            assert!(is_trusted(&indirect).unwrap());
            assert!(!trust(&indirect).unwrap());
            assert_eq!(trusted_paths().unwrap().len(), 1);
        });
    }
}
