//! `POST /v1/multiscan`, and the instance limits that decide how a scan is split.
//!
//! Detection is entirely server-side: this module ships bytes and interprets a
//! verdict. There is no detector, no regex and no rule here, and there must never
//! be one.

use serde::Deserialize;
use serde_json::{Value, json};

use ggshield_common::error::Error;
use ggshield_common::hash::sha256_hex;
use ggshield_config::config::{self, Config, Limits, SIZE_METADATA_OVERHEAD};
use ggshield_config::user_config::SecretConfig;

/// `_API_PATH_MAX_LENGTH` in secret_scanner.py.
const API_PATH_MAX_LENGTH: usize = 256;
const TIMEOUT_SECS: u64 = 60;

/// The TLS config to attach when `.gitguardian.yaml` set `insecure` (or v1
/// `allow_self_signed`): certificate verification off, matching `session.verify
/// = False` in `core/client.py`. `None` keeps ureq's default verifying config,
/// which is the only safe default and the only thing the non-insecure path uses.
fn insecure_tls(config: &Config) -> Option<ureq::tls::TlsConfig> {
    config.user.insecure.then(|| {
        ureq::tls::TlsConfig::builder()
            .disable_verification(true)
            .build()
    })
}

pub struct Document {
    pub content: String,
    pub filename: String,
}

/// One document's verdict. `Result.from_scan_result()` splits the API's policy
/// breaks in two, and both halves matter: `secrets` decides the block, while
/// `filtered_out` says whether the emptiness of `secrets` is the API's answer
/// or this project's ignore rules — Python's `ignored_secrets_count_by_kind`.
/// A verdict that depends on local configuration must not be cached.
pub struct DocumentResult {
    pub secrets: Vec<Secret>,
    pub filtered_out: usize,
}

/// How far the API got in checking whether a secret still works
/// (`translate_validity()`). An id we do not know is kept as text: the server can
/// add one, and showing its raw id beats showing "unknown".
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Validity {
    Unknown,
    CannotCheck,
    NoChecker,
    FailedToCheck,
    NotChecked,
    Invalid,
    Valid,
    #[serde(untagged)]
    Other(String),
}

impl Validity {
    /// The label the block message uses, which is always lower case.
    pub fn label(&self) -> String {
        match self {
            Validity::Unknown => "unknown",
            Validity::CannotCheck => "cannot check",
            Validity::NoChecker => "no checker",
            Validity::FailedToCheck => "failed to check",
            Validity::NotChecked => "not checked",
            Validity::Invalid => "invalid",
            Validity::Valid => "valid",
            Validity::Other(raw) => return raw.to_lowercase(),
        }
        .to_string()
    }
}

/// A `PolicyBreak` reduced to the fields the hook message actually reads.
#[derive(Debug, Deserialize)]
pub struct Secret {
    // The wire field is `type`; `break_type` is only pygitguardian's
    // internal name for it (PolicyBreakSchema, data_key="type").
    #[serde(rename = "type")]
    pub detector_display_name: String,
    #[serde(default)]
    pub validity: Option<Validity>,
    #[serde(default)]
    pub known_secret: bool,
    #[serde(default)]
    pub incident_url: Option<String>,
    #[serde(default)]
    pub matches: Vec<Match>,
}

#[derive(Debug, Deserialize)]
pub struct Match {
    #[serde(rename = "match")]
    pub value: String,
    // Needed for the ignore sha, which hashes "<match>,<match_type>" pairs
    // sorted by match_type. The wire field is `type`.
    #[serde(rename = "type")]
    pub match_type: String,
}

#[derive(Debug, Deserialize)]
struct RawPolicyBreak {
    policy: String,
    #[serde(default)]
    is_excluded: bool,
    #[serde(default)]
    diff_kind: Option<String>,
    #[serde(flatten)]
    secret: Secret,
}

#[derive(Debug, Deserialize)]
struct ScanResult {
    #[serde(default)]
    policy_breaks: Vec<RawPolicyBreak>,
}

/// `get_ignore_sha()`: sha256 over the policy break's matches rendered as
/// "<match>,<match_type>" and sorted by match_type only, stably. This is the
/// value users paste into `ignored_matches`, so it has to hash identically.
fn ignore_sha(matches: &[Match]) -> String {
    let mut sorted: Vec<&Match> = matches.iter().collect();
    sorted.sort_by(|a, b| a.match_type.cmp(&b.match_type));
    let hashable: String = sorted
        .iter()
        .map(|m| format!("{},{}", m.value, m.match_type))
        .collect();
    sha256_hex(&hashable)
}

/// `is_in_ignored_matches()`. An entry in `ignored_matches` is either the
/// ignore sha of the whole policy break or one of its literal match values.
fn is_in_ignored_matches(pb: &RawPolicyBreak, ignored: &[String]) -> bool {
    if !pb.policy.eq_ignore_ascii_case("secrets detection") {
        return true;
    }
    ignored.contains(&ignore_sha(&pb.secret.matches))
        || pb.secret.matches.iter().any(|m| ignored.contains(&m.value))
}

/// `compute_ignore_reason()`, in Python's branch order.
fn is_ignored(pb: &RawPolicyBreak, secret_config: &SecretConfig) -> bool {
    // Secrets that were removed rather than introduced.
    if matches!(pb.diff_kind.as_deref(), Some("deletion") | Some("context")) {
        return true;
    }
    // Excluded by the dashboard.
    if pb.is_excluded {
        return true;
    }
    if is_in_ignored_matches(pb, &secret_config.ignored_matches) {
        return true;
    }
    if secret_config
        .ignored_detectors
        .contains(&pb.secret.detector_display_name)
    {
        return true;
    }
    secret_config.ignore_known_secrets && pb.secret.known_secret
}

/// `Result.from_scan_result()`: drop the ignored breaks — unless `all_secrets`
/// is set, in which case they are kept and therefore still block.
fn keep(pb: &RawPolicyBreak, secret_config: &SecretConfig) -> bool {
    secret_config.all_secrets || !is_ignored(pb, secret_config)
}

/// This instance's scan limits, resolved once per run and memoised on the
/// `Config`.
///
/// Sending a document or a batch the instance would reject earns a 400, which on
/// this path means the whole event fails open unscanned — so the limits have to
/// be the instance's, not an assumption. In order:
///
/// 1. `GG_MAX_DOC_SIZE` / `GG_MAX_DOCS`, which `_start_scans()` also honours.
///    Handled by the accessors below, before this is ever called.
/// 2. This hook's own limits cache, which step 4 fills — the warm path when only
///    the native binary runs.
/// 3. ggshield's on-disk auth-check cache, still warm whenever `ggshield` itself
///    ran recently, and we cannot write that one (see `store_instance_limits`).
/// 4. One `/v1/metadata` fetch, whose answer is written back to step 2.
/// 5. The compiled-in defaults, on any failure.
///
/// Resolution is deferred until a document is actually about to be scanned, so an
/// invocation that scans nothing reads neither a cache file nor the network.
fn limits(config: &Config) -> Limits {
    *config.limits.get_or_init(|| resolve_limits(config))
}

fn resolve_limits(config: &Config) -> Limits {
    let default = Limits::default();
    // No token means no scan either, and both caches are keyed on it.
    let Ok(token) = config.token() else {
        return default;
    };
    if let Some(limits) = config::cached_instance_limits(&config.api_url, token) {
        return limits;
    }
    if let Some(cached) = config::cached_limits(&config.api_url, token) {
        return Limits {
            maximum_document_size: positive(cached.maximum_document_size)
                .unwrap_or(default.maximum_document_size),
            maximum_documents_per_scan: positive(cached.maximum_documents_per_scan)
                .unwrap_or(default.maximum_documents_per_scan),
            maximum_payload_size: positive(cached.maximum_payload_size)
                .map(net_payload_size)
                .unwrap_or(default.maximum_payload_size),
        };
    }
    let Some(body) = fetch_metadata(config) else {
        return default;
    };
    let limits = Limits {
        maximum_document_size: positive_at(
            &body,
            "secret_scan_preferences",
            "maximum_document_size",
        )
        .unwrap_or(default.maximum_document_size),
        maximum_documents_per_scan: positive_at(
            &body,
            "secret_scan_preferences",
            "maximum_documents_per_scan",
        )
        .unwrap_or(default.maximum_documents_per_scan),
        maximum_payload_size: positive_at(&body, "preferences", "general__maximum_payload_size")
            .map(net_payload_size)
            .unwrap_or(default.maximum_payload_size),
    };
    config::store_instance_limits(&config.api_url, token, limits);
    limits
}

/// The advertised ceiling covers the whole request; the budget for document bytes
/// is what is left once the framing is accounted for, as secret_scanner.py does.
fn net_payload_size(advertised: usize) -> usize {
    advertised.saturating_sub(SIZE_METADATA_OVERHEAD)
}

fn positive(value: Option<usize>) -> Option<usize> {
    value.filter(|value| *value > 0)
}

fn positive_at(body: &Value, parent: &str, key: &str) -> Option<usize> {
    let value = body.get(parent)?.get(key)?.as_u64()?;
    (value > 0).then_some(value as usize)
}

fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok()?.trim().parse().ok()
}

fn fetch_metadata(config: &Config) -> Option<Value> {
    let url = format!("{}/v1/metadata", config.api_url);
    let mut builder = ureq::get(&url)
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(TIMEOUT_SECS)));
    if let Some(tls) = insecure_tls(config) {
        builder = builder.tls_config(tls);
    }
    let mut response = builder
        .build()
        .header("Authorization", format!("Token {}", config.token().ok()?))
        .call()
        .ok()?;
    response.body_mut().read_json().ok()
}

/// This instance's per-document ceiling. A document over it is skipped rather
/// than sent, matching `_start_scans()`.
pub fn max_document_size(config: &Config) -> usize {
    env_usize("GG_MAX_DOC_SIZE").unwrap_or_else(|| limits(config).maximum_document_size)
}

/// How many documents this instance accepts in one scan.
pub fn max_documents_per_scan(config: &Config) -> usize {
    env_usize("GG_MAX_DOCS").unwrap_or_else(|| limits(config).maximum_documents_per_scan)
}

/// How many document bytes this instance accepts in one scan, all documents
/// together.
pub fn max_payload_size(config: &Config) -> usize {
    limits(config).maximum_payload_size
}

pub fn multiscan<'a>(
    config: &Config,
    agent: crate::payload::Agent,
    documents: impl IntoIterator<Item = &'a Document>,
) -> Result<Vec<DocumentResult>, Error> {
    let payload: Vec<Value> = documents
        .into_iter()
        .map(|doc| {
            // `_document_filename()`: basename first when `filename_only` is
            // set, then truncated to the LAST 256 characters.
            let filename = if config.user.secret.filename_only {
                let base = doc.filename.rsplit('/').next().unwrap_or_default();
                if base.is_empty() { &doc.filename } else { base }
            } else {
                &doc.filename
            };
            let length = filename.chars().count();
            let filename: String = filename
                .chars()
                .skip(length.saturating_sub(API_PATH_MAX_LENGTH))
                .collect();
            // Field order and the null `location` are pygitguardian's
            // DocumentSchema.
            json!({"filename": filename, "document": doc.content, "location": null})
        })
        .collect();
    let body = Value::Array(payload).to_string();

    let url = format!("{}/v1/multiscan?all_secrets=True", config.api_url);
    let mut builder = ureq::post(&url)
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(TIMEOUT_SECS)));
    if let Some(tls) = insecure_tls(config) {
        builder = builder.tls_config(tls);
    }
    let response = builder
        .build()
        .header("Authorization", format!("Token {}", config.token()?))
        .header("Content-Type", "application/json")
        // Telemetry ggshield sends on every scan; the backend segments on `mode`
        // and `GGShield-Agent-Name`.
        .header("mode", "ai_hook")
        .header("GGShield-Agent-Name", agent.name())
        .header("GGShield-Command-Path", "ggshield secret scan ai-hook")
        .header("GGShield-Version", env!("CARGO_PKG_VERSION"))
        .header(
            "User-Agent",
            concat!("ggshield-hook/", env!("CARGO_PKG_VERSION")),
        )
        .send(&body);

    let mut response = match response {
        Ok(response) => response,
        Err(e) => return Err(Error::scan(e.to_string())),
    };

    let status = response.status().as_u16();
    if status == 401 || status == 403 {
        return Err(Error::auth());
    }
    let text = response
        .body_mut()
        .read_to_string()
        .map_err(|e| Error::scan(e.to_string()))?;
    if status != 200 {
        let detail = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|v| v.get("detail").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_else(|| format!("HTTP {status}"));
        return Err(Error::scan(detail));
    }

    let results: Vec<ScanResult> =
        serde_json::from_str(&text).map_err(|e| Error::scan(format!("bad API response: {e}")))?;

    Ok(results
        .into_iter()
        .map(|result| split_result(result, &config.user.secret))
        .collect())
}

fn split_result(result: ScanResult, secret_config: &SecretConfig) -> DocumentResult {
    let total = result.policy_breaks.len();
    let secrets: Vec<Secret> = result
        .policy_breaks
        .into_iter()
        .filter(|pb| keep(pb, secret_config))
        .map(|pb| pb.secret)
        .collect();
    DocumentResult {
        filtered_out: total - secrets.len(),
        secrets,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A localhost `/v1/metadata` responder, and the count of requests it served.
    /// Nothing ever leaves the machine.
    fn metadata_api() -> (String, Arc<AtomicUsize>) {
        const BODY: &str = r#"{"preferences": {"general__maximum_payload_size": 1000000}, "secret_scan_preferences": {"maximum_document_size": 4096, "maximum_documents_per_scan": 5}}"#;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let hits = Arc::new(AtomicUsize::new(0));
        let served = Arc::clone(&hits);
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut line = String::new();
                // Read past the request line and headers; a GET carries no body.
                while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                    if line == "\r\n" {
                        break;
                    }
                    line.clear();
                }
                served.fetch_add(1, Ordering::SeqCst);
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
                    BODY.len()
                );
            }
        });
        (url, hits)
    }

    fn config_for(api_url: String) -> Config {
        Config::with_token(api_url, "token".into(), Default::default())
    }

    /// Backdate the entry the hook wrote by `seconds` — ageing it past its TTL is
    /// the one thing a test cannot wait out. Edited from the outside, so no
    /// production API exists purely for this.
    fn age_stored_entry(seconds: i64) {
        let dir = config::cache_dir().expect("cache dir");
        let path = std::fs::read_dir(&dir)
            .expect("read_dir")
            .flatten()
            .map(|e| e.path())
            .next()
            .expect("the fetch wrote an entry");
        let mut entry: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        let stored_at = entry["stored_at"].as_i64().expect("stored_at");
        entry["stored_at"] = (stored_at - seconds).into();
        // `write` truncates in place, so the file keeps the mode the hook gave it.
        std::fs::write(&path, entry.to_string()).expect("write");
    }

    /// GIVEN an instance whose limits this hook has never fetched
    /// WHEN they are resolved, and resolved again from a second process
    /// THEN the first run pays one `/v1/metadata` round trip and writes what it
    /// learned; the second answers from that file and makes no request at all.
    #[test]
    fn a_cold_resolution_fetches_once_and_a_warm_one_not_at_all() {
        let (_guard, _dir) = crate::verdict_cache::with_cache_dir();
        let (url, hits) = metadata_api();

        let cold = limits(&config_for(url.clone()));
        assert_eq!(cold.maximum_document_size, 4096);
        assert_eq!(cold.maximum_documents_per_scan, 5);
        assert_eq!(
            cold.maximum_payload_size,
            1_000_000 - SIZE_METADATA_OVERHEAD
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // A fresh `Config` is a fresh process as far as memoisation goes.
        let warm = limits(&config_for(url));
        assert_eq!(warm.maximum_document_size, 4096);
        assert_eq!(warm.maximum_documents_per_scan, 5);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "the warm run refetched");
    }

    /// GIVEN a limits entry this hook wrote longer ago than its TTL
    /// WHEN the limits are resolved
    /// THEN the instance is asked again and the answer replaces the stale entry,
    /// so an instance that lowers a limit is honoured within one TTL.
    #[test]
    fn an_expired_entry_is_refetched_and_rewritten() {
        let (_guard, _dir) = crate::verdict_cache::with_cache_dir();
        let (url, hits) = metadata_api();

        limits(&config_for(url.clone()));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        age_stored_entry(301);

        let refetched = limits(&config_for(url.clone()));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert_eq!(refetched.maximum_documents_per_scan, 5);
        // Rewritten, not merely refetched: the next run is warm again.
        limits(&config_for(url));
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    /// GIVEN an instance that cannot be reached
    /// WHEN the limits are resolved
    /// THEN the compiled-in defaults answer rather than nothing, and no entry is
    /// cached — a failed fetch must not pin a guess for the next five minutes.
    #[test]
    fn an_unreachable_instance_falls_back_to_the_defaults_without_caching_them() {
        let (_guard, _dir) = crate::verdict_cache::with_cache_dir();
        // Port 1 is reserved and unbound: connection refused, immediately.
        let url = "http://127.0.0.1:1".to_string();

        let resolved = limits(&config_for(url.clone()));
        assert_eq!(
            resolved.maximum_documents_per_scan,
            config::DEFAULT_MAX_DOCUMENTS_PER_SCAN
        );
        assert!(config::cached_instance_limits(&url, "token").is_none());
    }

    fn split(json: &str, secret_config: &SecretConfig) -> Vec<DocumentResult> {
        let results: Vec<ScanResult> = serde_json::from_str(json).expect("valid");
        results
            .into_iter()
            .map(|r| split_result(r, secret_config))
            .collect()
    }

    fn parse_with(json: &str, secret_config: &SecretConfig) -> Vec<Vec<Secret>> {
        split(json, secret_config)
            .into_iter()
            .map(|r| r.secrets)
            .collect()
    }

    fn parse(json: &str) -> Vec<Vec<Secret>> {
        parse_with(json, &SecretConfig::default())
    }

    const AWS: &str = r#"[{"policy_breaks": [
        {"policy": "Secrets detection", "type": "AWS Keys", "known_secret": true,
         "matches": [{"match": "AKIAsomething", "type": "client_id"},
                     {"match": "s3cr3t", "type": "client_secret"}]}]}]"#;

    /// GIVEN a policy break with two matches
    /// WHEN `ignored_matches` holds either one match value or the break's ignore sha
    /// THEN the break is dropped.
    #[test]
    fn ignored_matches_accepts_a_literal_value_or_the_ignore_sha() {
        let by_value = SecretConfig {
            ignored_matches: vec!["AKIAsomething".into()],
            ..SecretConfig::default()
        };
        assert!(parse_with(AWS, &by_value)[0].is_empty());

        // The sha is over both matches, sorted by match_type.
        let sha = ignore_sha(&[
            Match {
                value: "AKIAsomething".into(),
                match_type: "client_id".into(),
            },
            Match {
                value: "s3cr3t".into(),
                match_type: "client_secret".into(),
            },
        ]);
        let by_sha = SecretConfig {
            ignored_matches: vec![sha],
            ..SecretConfig::default()
        };
        assert!(parse_with(AWS, &by_sha)[0].is_empty());
    }

    /// GIVEN the same matches in two orders
    /// WHEN their ignore sha is computed
    /// THEN it is the same sha, so a user's pasted value keeps working.
    #[test]
    fn ignore_sha_is_order_independent() {
        let a = ignore_sha(&[
            Match {
                value: "b".into(),
                match_type: "client_secret".into(),
            },
            Match {
                value: "a".into(),
                match_type: "client_id".into(),
            },
        ]);
        let b = ignore_sha(&[
            Match {
                value: "a".into(),
                match_type: "client_id".into(),
            },
            Match {
                value: "b".into(),
                match_type: "client_secret".into(),
            },
        ]);
        assert_eq!(a, b);
    }

    /// GIVEN a config ignoring the detector, or ignoring known secrets
    /// WHEN a known secret from that detector is reported
    /// THEN it is dropped either way.
    #[test]
    fn ignored_detectors_and_known_secrets_are_honoured() {
        let by_detector = SecretConfig {
            ignored_detectors: ["AWS Keys".to_string()].into_iter().collect(),
            ..SecretConfig::default()
        };
        assert!(parse_with(AWS, &by_detector)[0].is_empty());

        let known = SecretConfig {
            ignore_known_secrets: true,
            ..SecretConfig::default()
        };
        assert!(parse_with(AWS, &known)[0].is_empty());
    }

    /// GIVEN `all_secrets` together with an ignore rule that matches
    /// WHEN the break is filtered
    /// THEN it is kept, and therefore still blocks.
    #[test]
    fn all_secrets_keeps_ignored_secrets_so_they_still_block() {
        let config = SecretConfig {
            ignored_matches: vec!["AKIAsomething".into()],
            all_secrets: true,
            ..SecretConfig::default()
        };
        assert_eq!(parse_with(AWS, &config)[0].len(), 1);
    }

    /// GIVEN a secrets-detection policy break
    /// WHEN the response is parsed
    /// THEN the detector name and the match reach the verdict.
    #[test]
    fn keeps_secret_policy_breaks() {
        let secrets = parse(
            r#"[{"policy_break_count": 1, "policies": [], "policy_breaks": [
                {"policy": "Secrets detection", "type": "AWS Keys",
                 "validity": "valid", "known_secret": false,
                 "matches": [{"match": "AKIAsomething", "type": "apikey"}]}]}]"#,
        );
        assert_eq!(secrets[0].len(), 1);
        assert_eq!(secrets[0][0].detector_display_name, "AWS Keys");
        assert_eq!(secrets[0][0].matches[0].value, "AKIAsomething");
    }

    /// GIVEN breaks that are excluded, not about secrets, or about a deletion
    /// WHEN the response is parsed
    /// THEN none of them blocks.
    #[test]
    fn drops_excluded_non_secret_and_deleted_breaks() {
        let secrets = parse(
            r#"[{"policy_breaks": [
                {"policy": "Secrets detection", "type": "A", "is_excluded": true, "matches": []},
                {"policy": "File extensions", "type": "B", "matches": []},
                {"policy": "Secrets detection", "type": "C", "diff_kind": "deletion", "matches": []}]}]"#,
        );
        assert!(secrets[0].is_empty());
    }

    /// GIVEN a response with no policy breaks
    /// WHEN it is parsed
    /// THEN no secrets are reported.
    #[test]
    fn empty_scan_result_yields_no_secrets() {
        assert_eq!(parse(r#"[{"policy_breaks": []}]"#)[0].len(), 0);
    }

    /// GIVEN a clean response, a locally-ignored break and a blocking break
    /// WHEN each is split into secrets and filtered-out counts
    /// THEN only the clean one has both empty, which is what makes it cacheable.
    #[test]
    fn locally_filtered_breaks_are_counted_separately() {
        let clean = &split(r#"[{"policy_breaks": []}]"#, &SecretConfig::default())[0];
        assert!(clean.secrets.is_empty() && clean.filtered_out == 0);

        let ignored = SecretConfig {
            ignored_matches: vec!["AKIAsomething".into()],
            ..SecretConfig::default()
        };
        let filtered = &split(AWS, &ignored)[0];
        assert!(filtered.secrets.is_empty() && filtered.filtered_out == 1);

        let blocked = &split(AWS, &SecretConfig::default())[0];
        assert_eq!((blocked.secrets.len(), blocked.filtered_out), (1, 0));
    }
}

/// GIVEN a validity id the API reported
/// WHEN it is turned into the label the message shows
/// THEN the known ids get their wording and an unknown one keeps its own text.
#[test]
fn validity_labels_cover_the_known_ids_and_keep_unknown_ones() {
    let label = |raw: &str| {
        serde_json::from_value::<Validity>(Value::String(raw.into()))
            .expect("any string is a validity")
            .label()
    };
    assert_eq!(label("valid"), "valid");
    assert_eq!(label("cannot_check"), "cannot check");
    assert_eq!(label("failed_to_check"), "failed to check");
    assert_eq!(label("Something-New"), "something-new");
}
