//! Clean-verdict cache.
//!
//! Everything here fails *closed*: every error path answers "not cached", which
//! means "scan". A cache that cannot be trusted must never turn into an allow.
//!
//! The on-disk format is the Python one — same filename, same key derivation —
//! so a machine running both implementations shares one cache instead of
//! keeping two half-warm ones.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::payload::sha256_hex;
use ggshield_common::secure_file;
use ggshield_config::config;
use ggshield_config::user_config::SecretConfig;

const FILENAME: &str = "ai_hook_verdicts.json";
/// The key covers everything the verdict depends on (see `key`), so an entry can
/// only go stale if the server's detection, or a secret's known/valid status,
/// changes — hence a short TTL.
const TTL_SECONDS: f64 = 15.0 * 60.0;
const MAX_ENTRIES: usize = 500;

/// The settings that change what we send or how we read the answer.
///
/// Only these: a setting that merely changes what we *print* would cost cache
/// misses without preventing a stale verdict. `filename_only` rewrites the
/// filename we send while the key holds the local one; `all_secrets` moves
/// locally-ignored breaks into the results, which is the guard deciding whether
/// a verdict is cacheable at all.
///
/// The ignore settings are deliberately absent: a verdict that depended on them
/// is never stored (see `scan_content`).
///
/// `source_uuid` is always empty: the hook never creates incidents, so both
/// implementations clear it. The
/// field is still emitted, because the string has to match Python's byte for byte
/// for the two implementations to share one cache.
fn config_fingerprint(secret_config: &SecretConfig) -> String {
    format!(
        "all_secrets={};filename_only={};source_uuid=",
        u8::from(secret_config.all_secrets),
        u8::from(secret_config.filename_only),
    )
}

/// Cache key for one document: everything the API's answer depends on.
///
/// Instance and token because the answer is per-workspace: custom detectors and
/// dashboard exclusions differ between them, so a verdict obtained with one
/// token says nothing about another.
///
/// NUL separates the parts: it cannot appear in a URL, a token or a path, so no
/// part can be shifted across the separator to impersonate another key.
pub fn key(
    instance: &str,
    api_key: &str,
    secret_config: &SecretConfig,
    filename: &str,
    content: &str,
) -> String {
    sha256_hex(
        &[
            instance,
            api_key,
            &config_fingerprint(secret_config),
            filename,
            content,
        ]
        .join("\0"),
    )
}

fn path() -> Option<PathBuf> {
    config::cache_dir().map(|dir| dir.join(FILENAME))
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// A timestamp in the future is not fresh: it is either clock skew or a forged
/// entry meant never to expire.
fn is_fresh(stored: f64, now: f64) -> bool {
    (0.0..TTL_SECONDS).contains(&(now - stored))
}

/// The cached clean verdicts, or an empty map if the cache cannot be trusted:
/// an untrusted file (see [`secure_file::read_if_trusted`]) and a corrupt one both
/// answer "nothing is cached", which means "scan".
fn load() -> HashMap<String, f64> {
    let Some(raw) = path().as_deref().and_then(secure_file::read_if_trusted) else {
        return HashMap::new();
    };
    // Anything that is not a plain {string: number} map is not a cache we wrote.
    serde_json::from_str(&raw).unwrap_or_default()
}

/// Whether `key` was scanned clean recently enough to skip the API call.
pub fn has_clean_verdict(key: &str) -> bool {
    load()
        .get(key)
        .is_some_and(|stored| is_fresh(*stored, now()))
}

/// Remember that `key` was scanned clean. Best effort: a lost or torn write
/// costs a cache miss, and a miss simply scans.
pub fn store_clean_verdict(key: &str) {
    let Some(path) = path() else {
        return;
    };
    let now = now();
    let mut verdicts = load();
    verdicts.insert(key.to_string(), now);
    // Drop expired entries and keep the cache bounded, newest kept first.
    let mut kept: Vec<(String, f64)> = verdicts
        .into_iter()
        .filter(|(_, stored)| is_fresh(*stored, now))
        .collect();
    kept.sort_by(|a, b| b.1.total_cmp(&a.1));
    kept.truncate(MAX_ENTRIES);

    if let Some(dir) = path.parent()
        && secure_file::create_dir_private(dir).is_err()
    {
        return;
    }
    let map: HashMap<String, f64> = kept.into_iter().collect();
    if let Ok(json) = serde_json::to_string(&map) {
        let _ = secure_file::write_private(&path, &json);
    }
}

/// `GG_CACHE_DIR` is process-wide, so every test that touches the cache — here
/// and in main.rs — takes this one lock.
#[cfg(test)]
static CACHE_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub fn with_cache_dir() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
    let guard = CACHE_ENV.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tempfile::tempdir().expect("tempdir");
    // SAFETY: serialised by the mutex above.
    unsafe { std::env::set_var("GG_CACHE_DIR", dir.path()) };
    (guard, dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GIVEN a cache key
    /// WHEN any part of it changes
    /// THEN the key changes, and no part can be shifted across the NUL separator
    /// to impersonate another key.
    #[test]
    fn every_part_of_the_key_changes_it() {
        let default = SecretConfig::default();
        let base = ("https://api.example.com", "token", "file.py", "content");
        let reference = key(base.0, base.1, &default, base.2, base.3);
        assert_ne!(
            reference,
            key(
                "https://other.example.com",
                base.1,
                &default,
                base.2,
                base.3
            )
        );
        assert_ne!(reference, key(base.0, "other", &default, base.2, base.3));
        assert_ne!(reference, key(base.0, base.1, &default, "other.py", base.3));
        assert_ne!(
            reference,
            key(base.0, base.1, &default, base.2, "other content")
        );
        for changed in [
            SecretConfig {
                all_secrets: true,
                ..SecretConfig::default()
            },
            SecretConfig {
                filename_only: true,
                ..SecretConfig::default()
            },
        ] {
            assert_ne!(reference, key(base.0, base.1, &changed, base.2, base.3));
        }
        // No part can be shifted across the separator to impersonate another key.
        assert_ne!(
            key("a", "b", &default, "c", "d"),
            key("a\0b", "c", &default, "d", "")
        );
    }

    /// GIVEN a secret config
    /// WHEN its cache fingerprint is rendered
    /// THEN it is byte for byte Python's, which is what lets both implementations
    /// share one cache file instead of keeping two half-warm ones.
    #[test]
    fn the_fingerprint_is_byte_for_byte_the_python_one() {
        assert_eq!(
            config_fingerprint(&SecretConfig::default()),
            "all_secrets=0;filename_only=0;source_uuid="
        );
        assert_eq!(
            config_fingerprint(&SecretConfig {
                all_secrets: true,
                filename_only: true,
                ..SecretConfig::default()
            }),
            "all_secrets=1;filename_only=1;source_uuid="
        );
    }

    /// GIVEN a stored clean verdict
    /// WHEN the cache is queried
    /// THEN that key hits and an unknown one does not.
    #[test]
    fn a_stored_verdict_hits_and_an_unknown_one_does_not() {
        let (_guard, _dir) = with_cache_dir();
        store_clean_verdict("some-key");
        assert!(has_clean_verdict("some-key"));
        assert!(!has_clean_verdict("another-key"));
    }

    /// GIVEN entries at various timestamps
    /// WHEN their freshness is tested
    /// THEN an expired one fails, and so does a future one — that is clock skew or
    /// an entry forged never to expire.
    #[test]
    fn expired_and_future_entries_are_not_fresh() {
        let now = now();
        assert!(is_fresh(now, now));
        assert!(is_fresh(now - TTL_SECONDS + 1.0, now));
        assert!(!is_fresh(now - TTL_SECONDS - 1.0, now));
        assert!(!is_fresh(now + 60.0, now));
    }

    /// GIVEN a cache over its entry cap containing an expired entry
    /// WHEN a new verdict is stored
    /// THEN the expired entry is dropped and the file stays bounded.
    #[test]
    fn the_cache_is_bounded_and_drops_expired_entries() {
        let (_guard, dir) = with_cache_dir();
        let path = dir.path().join(FILENAME);
        let stale = now() - TTL_SECONDS - 1.0;
        let mut seed: HashMap<String, f64> = (0..MAX_ENTRIES + 50)
            .map(|i| (format!("k{i}"), now()))
            .collect();
        seed.insert("expired".into(), stale);
        std::fs::write(&path, serde_json::to_string(&seed).expect("json")).expect("write");

        store_clean_verdict("fresh");
        let stored: HashMap<String, f64> =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        assert_eq!(stored.len(), MAX_ENTRIES);
        assert!(!stored.contains_key("expired"));
        assert!(stored.contains_key("fresh"));
    }

    /// GIVEN a cache file that is not a {string: number} map
    /// WHEN it is queried
    /// THEN it answers "not cached", which means "scan".
    #[test]
    fn a_corrupt_or_foreign_cache_is_ignored_rather_than_trusted() {
        let (_guard, dir) = with_cache_dir();
        let path = dir.path().join(FILENAME);
        for content in ["not json", "[1, 2, 3]", r#"{"k": "not a number"}"#] {
            std::fs::write(&path, content).expect("write");
            assert!(!has_clean_verdict("k"), "{content}");
        }
    }

    /// GIVEN a cache file another local user could write
    /// WHEN it is queried
    /// THEN it is refused, and the next write repairs its permissions instead of
    /// giving up on the cache for good.
    #[cfg(unix)]
    #[test]
    fn a_group_or_other_writable_cache_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (_guard, dir) = with_cache_dir();
        let path = dir.path().join(FILENAME);
        store_clean_verdict("k");
        assert!(has_clean_verdict("k"));

        for mode in [0o660, 0o606, 0o666] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
            assert!(!has_clean_verdict("k"), "{mode:o} must not be trusted");
        }
        store_clean_verdict("k");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(has_clean_verdict("k"));
    }

    /// GIVEN a symlink where the cache file should be
    /// WHEN it is queried
    /// THEN it is never followed: a symlink is not a file we wrote.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_cache_is_never_read() {
        let (_guard, dir) = with_cache_dir();
        let real = dir.path().join("elsewhere.json");
        std::fs::write(
            &real,
            serde_json::to_string(&HashMap::from([("k".to_string(), now())])).expect("json"),
        )
        .expect("write");
        std::os::unix::fs::symlink(&real, dir.path().join(FILENAME)).expect("symlink");
        assert!(!has_clean_verdict("k"));
    }
}
