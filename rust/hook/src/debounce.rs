//! Payload debounce: one scan per event, one verdict for every hook that asks.
//!
//! Some setups install hooks in several assistants' config formats, so one event
//! reaches us twice with byte-identical stdin. The first invocation scans and
//! stores what it emitted; the next one with the same payload replays it, so
//! both hooks answer alike and the event still costs a single API call.
//!
//! Everything here fails towards *scanning*: an entry that cannot be read,
//! trusted or parsed is a miss, and a miss scans. Silence is never an outcome.
//!
//! Constraint: the verdict is stored once the scan is done, so two invocations
//! that overlap both scan. That costs a round trip and still leaves both with a
//! verdict; only a lock held across the API call could collapse them.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::output::Emission;
use crate::payload::sha256_hex;
use ggshield_common::secure_file;
use ggshield_config::config;

/// Ours alone, unlike the clean-verdict cache: hooks.py keeps its own
/// `latest_ai_hook.txt`, which holds a bare hash and no verdict to replay.
const FILENAME: &str = "ai_hook_debounce.json";

/// The hooks of one event fire within milliseconds of each other. Past a minute
/// a replay would answer for content that has had time to change, so the entry
/// expires and the next invocation scans.
const TTL_SECONDS: i64 = 60;

/// A block message embeds the redacted tool output, which some agents make
/// arbitrarily large, and the cache dir is no place for megabytes. Over the cap
/// nothing is stored: the next invocation scans, which costs a round trip rather
/// than a lost verdict.
const MAX_ENTRY_BYTES: usize = 256 * 1024;

/// The last event's verdict. `stored_at` rather than an absolute expiry, so a
/// future timestamp reads as *not fresh*.
#[derive(Serialize, Deserialize)]
struct Entry {
    payload_hash: String,
    stored_at: i64,
    emission: Emission,
}

fn path() -> Option<PathBuf> {
    config::cache_dir().map(|dir| dir.join(FILENAME))
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The debounce key: the raw payload, trimmed as hooks.py trims it.
pub fn hash(stdin_content: &str) -> String {
    sha256_hex(stdin_content.trim())
}

/// The verdict another invocation emitted for this very payload, if one is
/// stored and still fresh.
pub fn replay(hash: &str) -> Option<Emission> {
    let raw = secure_file::read_if_trusted(&path()?)?;
    let entry: Entry = serde_json::from_str(&raw).ok()?;
    let age = now().checked_sub(entry.stored_at)?;
    (entry.payload_hash == hash && (0..TTL_SECONDS).contains(&age)).then_some(entry.emission)
}

/// Remember what this payload was answered with. Best effort: a lost write
/// costs the next hook a scan of its own.
pub fn store(hash: &str, emission: &Emission) {
    let Some(dir) = config::cache_dir() else {
        return;
    };
    let Ok(json) = serde_json::to_string(&Entry {
        payload_hash: hash.to_string(),
        stored_at: now(),
        emission: emission.clone(),
    }) else {
        return;
    };
    if json.len() > MAX_ENTRY_BYTES || secure_file::create_dir_private(&dir).is_err() {
        return;
    }
    // Write beside the target and rename: two hooks for one event run in
    // parallel, and rename within one directory is atomic, so neither ever reads
    // half of the other's entry. The pid keeps them off each other's temp file.
    let temp = dir.join(format!("{FILENAME}.{}.tmp", std::process::id()));
    if secure_file::write_private(&temp, &json).is_err()
        || std::fs::rename(&temp, dir.join(FILENAME)).is_err()
    {
        let _ = std::fs::remove_file(&temp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict_cache::with_cache_dir;
    use serde_json::json;

    fn emissions() -> [Emission; 3] {
        [
            Emission::Stdout(json!({"decision": "block", "reason": "nope"}), 0),
            Emission::Stderr("nope".into(), 2),
            Emission::Silent(0),
        ]
    }

    /// GIVEN each of the three ways an adapter can answer
    /// WHEN it is stored and replayed
    /// THEN it comes back whole, exit code included, and only for its own payload.
    #[test]
    fn every_emission_round_trips_for_its_own_payload_only() {
        let (_guard, _dir) = with_cache_dir();
        for emission in emissions() {
            store(&hash(" event "), &emission);
            assert_eq!(replay(&hash("event")), Some(emission));
            assert_eq!(replay(&hash("another event")), None);
        }
    }

    /// GIVEN an entry older than the TTL, and one stamped in the future
    /// WHEN it is replayed
    /// THEN neither is reused, so the payload is scanned again.
    #[test]
    fn a_stale_or_future_entry_is_not_replayed() {
        let (_guard, dir) = with_cache_dir();
        for stored_at in [now() - TTL_SECONDS - 1, now() + 60] {
            let entry = json!({
                "payload_hash": hash("event"),
                "stored_at": stored_at,
                "emission": {"Silent": 0},
            });
            std::fs::write(dir.path().join(FILENAME), entry.to_string()).expect("write");
            assert_eq!(replay(&hash("event")), None, "{stored_at}");
        }
    }

    /// GIVEN a debounce file that is not an entry we wrote
    /// WHEN it is replayed
    /// THEN it answers "nothing stored", which means "scan".
    #[test]
    fn a_corrupt_entry_is_not_replayed() {
        let (_guard, dir) = with_cache_dir();
        for content in [
            "not json",
            "{}",
            r#"{"payload_hash": "x", "stored_at": 0}"#,
            r#"{"payload_hash": "x", "stored_at": 0, "emission": {"Nonsense": 1}}"#,
        ] {
            std::fs::write(dir.path().join(FILENAME), content).expect("write");
            assert_eq!(replay("x"), None, "{content}");
        }
    }

    /// GIVEN a verdict larger than the cap
    /// WHEN it is stored
    /// THEN nothing is kept, and the next invocation scans rather than replaying.
    #[test]
    fn an_oversize_verdict_is_not_stored() {
        let (_guard, _dir) = with_cache_dir();
        let huge = Emission::Stderr("x".repeat(MAX_ENTRY_BYTES + 1), 2);
        store(&hash("event"), &huge);
        assert_eq!(replay(&hash("event")), None);
    }
}
