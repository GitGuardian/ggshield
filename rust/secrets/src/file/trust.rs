//! Which dotenv files this user has approved for `activate`'s shell hook.
//!
//! Entries pin `(canonical path, SHA-256 of contents)` so any edit revokes
//! trust, as with `direnv allow`; the hash must be cryptographic because trust
//! is decided by comparing it. Stored per-user, never in the project.

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

/// Whether `path`'s current contents are approved; fails closed.
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
    // Replace rather than accumulate, so an old digest can never come back.
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
    // Same reader as the provider, so the digest covers the bytes actually loaded.
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

/// Resolved when possible; an unresolvable path just won't match, which is safe.
fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Read the store; unreadable lines are skipped so damage never locks out the shell.
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
    atomic::replace_bytes(&path, out.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
// A failed unwrap in a test is the assertion failing.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Gives each test its own home, serialised because env vars are process-wide.
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

            std::fs::write(&env, "A=1\nPROMPT_COMMAND=touch /tmp/x\n").unwrap();
            assert!(!is_trusted(&env).unwrap());

            // Reverting must not silently re-trust the old digest.
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
            let indirect = home.join(".").join("project.env");
            assert!(is_trusted(&indirect).unwrap());
            assert!(!trust(&indirect).unwrap());
            assert_eq!(trusted_paths().unwrap().len(), 1);
        });
    }
}
