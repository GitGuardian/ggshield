//! API token and instance URL resolution.
//!
//! Mirrors `Config.get_api_key_and_source()`, `AuthConfig.load()` and
//! `token_store.py`. The `.gitguardian.yaml` half of `Config` lives in
//! `user_config.rs`.

use std::cell::OnceCell;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::user_config::{self, UserConfig};
use ggshield_common::error::Error;
use ggshield_common::hash::sha256_hex;
use ggshield_common::secure_file;

#[cfg(target_os = "linux")]
use secret_service::{EncryptionType, blocking::SecretService};
#[cfg(target_os = "linux")]
use std::collections::HashMap;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
#[cfg(windows)]
use windows_sys::Win32::Security::Credentials::{
    CRED_TYPE_GENERIC, CREDENTIALW, CredFree, CredReadW,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
};
#[cfg(windows)]
use windows_sys::Win32::System::IO::OVERLAPPED;

// The service name every keyring backend stores under
// (`keyring.set_password("ggshield", instance_url, token)`, token_store.py).
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux", windows)),
    allow(dead_code)
)]
pub const KEYRING_SERVICE: &str = "ggshield";
pub const KEYRING_SENTINEL: &str = "__KEYRING__";
pub const DEFAULT_INSTANCE_URL: &str = "https://dashboard.gitguardian.com";

const TRACKED_ENV_VARS: [&str; 3] = [
    "GITGUARDIAN_INSTANCE",
    "GITGUARDIAN_API_URL",
    "GITGUARDIAN_API_KEY",
];

/// pygitguardian's `DOCUMENT_SIZE_THRESHOLD_BYTES`: the default per-document
/// ceiling, and the size past which the ai-hook stops caching a verdict.
pub const MAXIMUM_DOCUMENT_SIZE: usize = 1_048_576;
/// pygitguardian's `MULTI_DOCUMENT_LIMIT`. One document past the instance's own
/// value the API answers 400, which in this hook means failing open.
pub const DEFAULT_MAX_DOCUMENTS_PER_SCAN: usize = 20;
/// `_SIZE_METADATA_OVERHEAD` (secret_scanner.py): request framing that any
/// advertised payload ceiling has to leave room for.
pub const SIZE_METADATA_OVERHEAD: usize = 10_240;
/// pygitguardian's `MAXIMUM_PAYLOAD_SIZE` minus the framing overhead: the bytes
/// one scan may carry, all its documents together.
pub const MAXIMUM_PAYLOAD_SIZE: usize = 2_621_440 - SIZE_METADATA_OVERHEAD;

/// This instance's scan limits. `Default` is the compiled-in set.
///
/// `maximum_payload_size` is the *net* document budget, i.e. already reduced by
/// `SIZE_METADATA_OVERHEAD`, not the ceiling the API advertises.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Limits {
    pub maximum_document_size: usize,
    pub maximum_documents_per_scan: usize,
    pub maximum_payload_size: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            maximum_document_size: MAXIMUM_DOCUMENT_SIZE,
            maximum_documents_per_scan: DEFAULT_MAX_DOCUMENTS_PER_SCAN,
            maximum_payload_size: MAXIMUM_PAYLOAD_SIZE,
        }
    }
}

/// The scan limits ggshield's auth-check cache holds for one (instance, token)
/// pair. `None` fields were absent from the cache entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct CachedLimits {
    pub maximum_document_size: Option<usize>,
    pub maximum_documents_per_scan: Option<usize>,
    /// The advertised whole-request ceiling, before `SIZE_METADATA_OVERHEAD`.
    pub maximum_payload_size: Option<usize>,
}

/// `auth_check.yaml` as `ggshield/core/auth_check_cache.py` writes it, reduced to
/// the scan limits.
#[derive(Debug, Default, Deserialize)]
struct AuthCheckCache {
    #[serde(default)]
    key_hash: String,
    #[serde(default)]
    expires_at: i64,
    #[serde(default)]
    maximum_payload_size: Option<usize>,
    #[serde(default)]
    secret_scan_preferences: Option<CachedScanPreferences>,
}

#[derive(Debug, Default, Deserialize)]
struct CachedScanPreferences {
    #[serde(default)]
    maximum_document_size: Option<usize>,
    #[serde(default)]
    maximum_documents_per_scan: Option<usize>,
}

/// The limits ggshield recorded the last time it verified this token, from
/// `check_client_api_key()`'s `/v1/metadata` fetch, so whichever implementation
/// ran last answers for the other. Read-only to us, and every failure is a miss.
pub fn cached_limits(api_url: &str, token: &str) -> Option<CachedLimits> {
    let raw = std::fs::read_to_string(cache_dir()?.join("auth_check.yaml")).ok()?;
    let cache: AuthCheckCache = serde_yaml_ng::from_str(&raw).ok()?;
    if cache.key_hash != cache_key(api_url, token) || cache.expires_at < now_unix() {
        return None;
    }
    let preferences = cache.secret_scan_preferences.unwrap_or_default();
    Some(CachedLimits {
        maximum_document_size: preferences.maximum_document_size,
        maximum_documents_per_scan: preferences.maximum_documents_per_scan,
        maximum_payload_size: cache.maximum_payload_size,
    })
}

/// The hook's *own* limits cache, next to the verdict cache. `auth_check.yaml`
/// above is read-only to us because it also short-circuits Python's token-scopes
/// check and carries `remediation_messages` and `secrets_engine_version`; this one
/// is ours to write, so it stays warm when only the native binary runs.
const LIMITS_FILENAME: &str = "ai_hook_limits.json";

/// `auth_check.yaml`'s own expiry, so an instance that lowers a limit sees it
/// applied within five minutes whichever hook is installed.
const LIMITS_TTL_SECONDS: i64 = 300;

/// One (instance, token) pair's limits, as stored. `stored_at` rather than an
/// absolute expiry, so a future timestamp reads as *not fresh*.
#[derive(Debug, Serialize, Deserialize)]
struct LimitsCacheEntry {
    key: String,
    stored_at: i64,
    limits: Limits,
}

/// Python's `auth_check.yaml` key derivation: per instance *and* token, so
/// switching either cannot reuse the other's limits. NUL separates the parts, so
/// no part can be shifted across the separator to forge another key.
fn cache_key(api_url: &str, token: &str) -> String {
    sha256_hex(&format!("{api_url}\0{token}"))
}

/// The limits this hook last fetched for (`api_url`, `token`), or `None` when
/// there is no entry we can trust. Every failure is a miss, which costs one
/// `/v1/metadata` fetch and never a wrong limit.
pub fn cached_instance_limits(api_url: &str, token: &str) -> Option<Limits> {
    let raw = secure_file::read_if_trusted(&cache_dir()?.join(LIMITS_FILENAME))?;
    let entry: LimitsCacheEntry = serde_json::from_str(&raw).ok()?;
    let age = now_unix().checked_sub(entry.stored_at)?;
    if entry.key != cache_key(api_url, token) || !(0..LIMITS_TTL_SECONDS).contains(&age) {
        return None;
    }
    // A zero is not a limit: `max_documents_per_scan` drives the chunking loop.
    let limits = entry.limits;
    [
        limits.maximum_document_size,
        limits.maximum_documents_per_scan,
        limits.maximum_payload_size,
    ]
    .iter()
    .all(|value| *value > 0)
    .then_some(limits)
}

/// Remember the limits fetched for (`api_url`, `token`). Best effort: a lost
/// write costs the next invocation a round trip, nothing more.
pub fn store_instance_limits(api_url: &str, token: &str, limits: Limits) {
    let Some(dir) = cache_dir() else {
        return;
    };
    if secure_file::create_dir_private(&dir).is_err() {
        return;
    }
    let Ok(json) = serde_json::to_string(&LimitsCacheEntry {
        key: cache_key(api_url, token),
        stored_at: now_unix(),
        limits,
    }) else {
        return;
    };
    // Write beside the target and rename: the hook fires twice per tool call and
    // the two runs overlap, and rename within one directory is atomic. The pid
    // keeps two overlapping writers off each other's temp file.
    let temp = dir.join(format!("{LIMITS_FILENAME}.{}.tmp", std::process::id()));
    if secure_file::write_private(&temp, &json).is_err()
        || std::fs::rename(&temp, dir.join(LIMITS_FILENAME)).is_err()
    {
        let _ = std::fs::remove_file(&temp);
    }
}

#[derive(Debug)]
pub struct Config {
    pub api_url: String,
    /// Where the token comes from, decided at resolve time.
    token_source: TokenSource,
    /// Read from the credential store on first use, failure included: see
    /// [`Config::token`].
    token: OnceCell<Result<String, Error>>,
    pub user: UserConfig,
    /// Instance limits, resolved at most once per run. The hook's `api` module
    /// owns the resolution order; this is where the answer is memoised.
    pub limits: OnceCell<Limits>,
}

#[derive(Debug)]
enum TokenSource {
    /// Already in hand: `GITGUARDIAN_API_KEY`, or a plain token in the YAML.
    Plain(String),
    /// The YAML held the sentinel, so the token is in the OS credential store,
    /// keyed by this instance URL. Reading it pops the macOS Keychain dialog, so
    /// it is deferred until something needs the token.
    Keyring(String),
}

impl Config {
    /// The API token, resolved on first use and memoised for the rest of the
    /// process, failure included: two call sites need it and re-reading would take
    /// the keyring lock twice. Lazy because on macOS an unsigned or newly rebuilt
    /// binary is not in the Keychain item's ACL, so the read prompts.
    ///
    /// One intentional divergence: Python hydrates the keyring while loading the
    /// config, so an unreadable credential store fails open with a warning even
    /// for an invocation that would not have scanned anything; here it stays
    /// silent. Every non-keyring failure is still raised eagerly by `resolve()`.
    pub fn token(&self) -> Result<&str, Error> {
        self.token
            .get_or_init(|| match &self.token_source {
                TokenSource::Plain(token) => Ok(token.clone()),
                TokenSource::Keyring(instance_url) => keyring_token(instance_url),
            })
            .as_deref()
            .map_err(Clone::clone)
    }

    /// A config with a token already in hand, for tests and for callers that
    /// never touch the credential store.
    pub fn with_token(api_url: String, token: String, user: UserConfig) -> Self {
        Config {
            api_url,
            token_source: TokenSource::Plain(token),
            token: OnceCell::new(),
            user,
            limits: OnceCell::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct AuthConfig {
    #[serde(default)]
    instances: Vec<InstanceConfig>,
}

#[derive(Debug, Deserialize)]
struct InstanceConfig {
    #[serde(default)]
    url: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    accounts: Vec<AccountConfig>,
}

#[derive(Debug, Deserialize)]
struct AccountConfig {
    #[serde(default)]
    token: String,
    /// RFC3339 in practice, parsed lazily by `is_expired`.
    #[serde(default, alias = "expire-at")]
    expire_at: Option<String>,
}

/// `get_config_dir()`, i.e. platformdirs' `user_config_dir("ggshield",
/// "GitGuardian")`. Windows needs its own arm: platformdirs' `user_config_dir` is
/// `user_data_dir`, i.e. `%LOCALAPPDATA%\GitGuardian\ggshield`, while
/// `dirs::config_dir()` returns Roaming `%APPDATA%`.
pub fn config_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("GG_CONFIG_DIR") {
        return Some(PathBuf::from(dir));
    }
    #[cfg(windows)]
    let base = dirs::data_local_dir().map(|d| d.join("GitGuardian").join("ggshield"));
    #[cfg(not(windows))]
    let base = dirs::config_dir().map(|d| d.join("ggshield"));
    base
}

/// `get_cache_dir()`, i.e. platformdirs' `user_cache_dir("ggshield",
/// "GitGuardian")`, whose Windows arm adds a `Cache` component.
pub fn cache_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("GG_CACHE_DIR") {
        return Some(PathBuf::from(dir));
    }
    #[cfg(windows)]
    let base = dirs::data_local_dir().map(|d| d.join("GitGuardian").join("ggshield").join("Cache"));
    #[cfg(not(windows))]
    let base = dirs::cache_dir().map(|d| d.join("ggshield"));
    base
}

/// The `GITGUARDIAN_*` bindings a `.env` contributes, in file order.
type DotEnv = Vec<(String, String)>;

/// One variable, `.env` first: `ggshield` loads the file with
/// `load_dotenv(dot_env_path, override=True)` (`core/env_utils.py`), so a value in
/// the file replaces the process environment. Last binding wins within the file,
/// as the file is collected into a dict there.
fn env_var(dotenv: &DotEnv, key: &str) -> Option<String> {
    dotenv
        .iter()
        .rev()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.clone())
        .or_else(|| std::env::var(key).ok())
}

/// The instance and token settings a `.env` overrides for this run. This binary
/// has to resolve the *same* instance and token the CLI would: a self-hosted
/// customer's `.env` names their own instance, so ignoring the file would ship
/// their content to the SaaS API. `dotenvy`'s `*_iter` API yields the bindings
/// without exporting them, and only the three tracked variables are applied.
///
/// Searches the two locations the CLI looks at: the cwd, then the git root (or
/// `GITGUARDIAN_DOTENV_PATH` when set); `GITGUARDIAN_DONT_LOAD_ENV` disables it.
///
/// One accepted difference from the CLI's own parser: `dotenvy` expands an
/// *unbraced* `$VAR`, where the CLI keeps it literal. Braced `${VAR}` is expanded
/// by both.
fn dotenv_overrides() -> Result<DotEnv, Error> {
    if std::env::var("GITGUARDIAN_DONT_LOAD_ENV")
        .is_ok_and(|v| !matches!(v.to_lowercase().as_str(), "" | "0" | "false" | "no"))
    {
        return Ok(DotEnv::new());
    }
    let mut candidates = Vec::new();
    if let Ok(explicit) = std::env::var("GITGUARDIAN_DOTENV_PATH") {
        candidates.push(PathBuf::from(explicit));
    } else {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        candidates.push(cwd.join(".env"));
        candidates.push(user_config::project_root().join(".env"));
    }

    for path in candidates {
        // The CLI stops at the first `.env` it finds; a candidate that cannot be
        // opened is not one.
        let Ok(bindings) = dotenvy::from_path_iter(&path) else {
            continue;
        };
        let mut found = DotEnv::new();
        // A rejected line does not stop the iterator, and an oddity in a project's
        // own variables must not cost a scan. Which line was rejected cannot be
        // read off the error: `dotenvy` reports the whole line for a malformed
        // name but only the value text for a bad escape.
        let mut rejected = false;
        for binding in bindings {
            match binding {
                Ok((key, value)) => {
                    if TRACKED_ENV_VARS.contains(&key.as_str()) {
                        found.push((key, value));
                    }
                }
                Err(_) => rejected = true,
            }
        }
        // So blame is attributed from the result instead: a file that appears to
        // bind one of the three more times than `dotenvy` yielded it has had that
        // binding dropped, which selects the wrong server or credential. Decline,
        // and name the variable.
        if rejected
            && let Ok(content) = std::fs::read_to_string(&path)
            && let Some(var) = TRACKED_ENV_VARS.into_iter().find(|var| {
                bindings_of(&content, var) > found.iter().filter(|(key, _)| key == var).count()
            })
        {
            return Err(Error::unimplemented(
                format!(
                    "a {var} binding that is not valid `.env` syntax ({})",
                    path.display()
                ),
                "Fix that line, or set the GITGUARDIAN_* variables in the \
                 environment instead.",
            ));
        }
        return Ok(found);
    }
    Ok(DotEnv::new())
}

/// How many lines of `content` look like a binding of `key`: the name at the
/// start of a line, optionally after `export`, then `=`. Deliberately coarse: it
/// only decides whether a *rejected* line was one of ours, and over-counting can
/// only add a decline on a file that already has a line `dotenvy` refused.
fn bindings_of(content: &str, key: &str) -> usize {
    content
        .lines()
        .filter(|line| {
            let line = line.trim_start();
            let line = line.strip_prefix("export").map_or(line, str::trim_start);
            line.strip_prefix(key)
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        })
        .count()
}

fn is_saas_netloc(netloc: &str) -> bool {
    if !(netloc.ends_with(".gitguardian.com") || netloc.ends_with(".gitguardian.tech")) {
        return false;
    }
    let first = netloc.split('.').next().unwrap_or_default();
    first == "dashboard"
        || first == "api"
        || first.starts_with("dashboard-")
        || first.starts_with("api-")
}

/// `dashboard_to_api_url()`. SaaS swaps the host label, self-hosted appends
/// `/exposed` to the path.
pub fn dashboard_to_api_url(dashboard_url: &str) -> String {
    let url = dashboard_url.trim_end_matches('/');
    let url = url.strip_suffix("/v1").unwrap_or(url);
    let Some((scheme, rest)) = url.split_once("://") else {
        return format!("{url}/exposed");
    };
    let (netloc, path) = match rest.split_once('/') {
        Some((netloc, path)) => (netloc, format!("/{path}")),
        None => (rest, String::new()),
    };
    if is_saas_netloc(netloc) {
        format!(
            "{scheme}://{}{path}",
            netloc.replacen("dashboard", "api", 1)
        )
    } else {
        format!("{scheme}://{netloc}{path}/exposed")
    }
}

/// `api_to_dashboard_url()`. Not the inverse of `dashboard_to_api_url()` for
/// self-hosted URLs without the `/exposed` suffix: it strips the suffix only when
/// present, so `https://gg.example.com` maps to itself and picks the suffix *up*
/// on the way back. Python does this round trip on `GITGUARDIAN_API_URL` too.
pub fn api_to_dashboard_url(api_url: &str) -> String {
    let url = api_url.trim_end_matches('/');
    let url = url.strip_suffix("/v1").unwrap_or(url);
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let (netloc, path) = match rest.split_once('/') {
        Some((netloc, path)) => (netloc, format!("/{path}")),
        None => (rest, String::new()),
    };
    if is_saas_netloc(netloc) {
        format!(
            "{scheme}://{}{path}",
            netloc.replacen("api", "dashboard", 1)
        )
    } else {
        let path = path.strip_suffix("/exposed").unwrap_or(&path);
        format!("{scheme}://{netloc}{path}")
    }
}

/// `validate_instance_url()` / `api_to_dashboard_url()` in `core/url_utils.py`:
/// anything but `https` is refused, so the token and the scanned content cannot
/// travel in the clear. A loopback host is the exception, for a local instance —
/// and `127.0.0.1` is allowed only for a *dashboard* URL, as in Python.
///
/// Python raises a `UsageError`, which `ai_hook_cmd`'s `except Exception` turns
/// into this same fail-open warning.
fn validate_scheme(url: &str, kind: &str, loopback: &[&str]) -> Result<(), Error> {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    if scheme == "https" || loopback.iter().any(|host| rest.starts_with(host)) {
        return Ok(());
    }
    Err(Error::scan(format!(
        "Invalid scheme for {kind} URL '{url}', expected HTTPS"
    )))
}

fn validate_dashboard_url(url: &str) -> Result<(), Error> {
    validate_scheme(url, "dashboard", &["localhost", "127.0.0.1"])
}

/// The instance the scan should talk to, as a *dashboard* URL.
/// `Config.get_instance_name_and_source()`, in its priority order, minus the
/// `--instance` flag (the hook is always invoked without arguments).
fn instance_name(user: &UserConfig, dotenv: &DotEnv) -> Result<String, Error> {
    if let Some(url) = env_var(dotenv, "GITGUARDIAN_INSTANCE") {
        validate_dashboard_url(&url)?;
        return Ok(url.trim_end_matches('/').to_string());
    }
    if let Some(url) = env_var(dotenv, "GITGUARDIAN_API_URL") {
        validate_scheme(&url, "API", &["localhost"])?;
        return Ok(api_to_dashboard_url(&url));
    }
    if let Some(url) = &user.instance {
        return Ok(url.clone());
    }
    Ok(DEFAULT_INSTANCE_URL.to_string())
}

pub fn resolve() -> Result<Config, Error> {
    let dotenv = dotenv_overrides()?;
    let user = user_config::load()?;

    let instance = instance_name(&user, &dotenv)?;
    // `Config.api_url` validates again, which is what catches a `.gitguardian.yaml`
    // `instance:` — the only source above that does not carry its own check.
    validate_dashboard_url(&instance)?;
    let api_url = dashboard_to_api_url(&instance);

    // Env var wins over everything, short-circuiting keychain access as
    // `AuthConfig.load()` does.
    if let Some(token) = env_var(&dotenv, "GITGUARDIAN_API_KEY")
        && !token.is_empty()
    {
        return Ok(Config::with_token(api_url, token, user));
    }

    let token_source = token_source_for_instance(&instance)?;
    Ok(Config {
        api_url,
        token_source,
        token: OnceCell::new(),
        user,
        limits: OnceCell::new(),
    })
}

/// `getenv_bool()` (utils/os.py): set to anything other than `false` or `0`,
/// case-insensitively, counts as true — including the empty string.
fn getenv_bool(key: &str) -> bool {
    std::env::var(key).is_ok_and(|v| !matches!(v.to_lowercase().as_str(), "false" | "0"))
}

fn auth_config_path() -> Result<PathBuf, Error> {
    config_dir()
        .map(|d| d.join("auth_config.yaml"))
        .ok_or_else(|| Error::scan("could not locate the ggshield config directory"))
}

fn token_source_for_instance(instance: &str) -> Result<TokenSource, Error> {
    let path = auth_config_path()?;
    let raw = std::fs::read_to_string(&path).map_err(|_| Error::auth())?;
    let config: AuthConfig =
        serde_yaml_ng::from_str(&raw).map_err(|e| Error::fatal(format!("{path:?}: {e}")))?;

    let inst = config
        .instances
        .iter()
        .find(|i| i.url == instance || i.name.as_deref() == Some(instance))
        .ok_or_else(Error::auth)?;

    let account = inst.accounts.first().ok_or_else(Error::auth)?;
    if is_expired(account.expire_at.as_deref()) {
        return Err(Error::auth());
    }
    if account.token.is_empty() {
        return Err(Error::auth());
    }
    // `_hydrate_from_keyring`: the sentinel means the real token lives in the OS
    // credential store; any other value IS the token (auth_config.py:237).
    if account.token == KEYRING_SENTINEL {
        // `GGSHIELD_NO_KEYRING` makes Python pick the FileTokenStore, which cannot
        // hydrate the sentinel: the blank token fails auth at client creation,
        // before the debounce, so it is eager here too.
        if getenv_bool("GGSHIELD_NO_KEYRING") {
            return Err(Error::auth());
        }
        return Ok(TokenSource::Keyring(inst.url.clone()));
    }
    Ok(TokenSource::Plain(account.token.clone()))
}

/// `InstanceConfig.expired`. Python compares an offset-bearing ISO-8601 timestamp
/// against an aware "now" and raises on anything else, so an unparseable value is
/// treated as expired here rather than vouched for.
fn is_expired(expire_at: Option<&str>) -> bool {
    let Some(raw) = expire_at
        .map(str::trim)
        .filter(|raw| !raw.is_empty() && *raw != "null")
    else {
        return false;
    };
    match DateTime::parse_from_rfc3339(raw) {
        Ok(expiry) => expiry.to_utc() <= Utc::now(),
        Err(_) => true,
    }
}

fn now_unix() -> i64 {
    Utc::now().timestamp()
}

/// `token_store.py`'s `keyring.lock`: the same file, so the two implementations
/// exclude each other and not just their own kind.
const KEYRING_LOCK_FILENAME: &str = "keyring.lock";

/// `_KEYRING_LOCK_TIMEOUT`. Past it we read unlocked: a stuck holder must never
/// hang the agent this hook runs inside.
const KEYRING_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// filelock's default `poll_interval`, so both sides retry at the same cadence.
const KEYRING_LOCK_POLL: Duration = Duration::from_millis(50);

/// Take `token_store.py`'s keyring lock, held for as long as the returned file
/// lives, or `None` when it could not be taken within `timeout` — no lock is a
/// degraded read, no read is a missed scan.
///
/// Concurrent reads of the OS credential store can fail (macOS securityd rejects
/// most simultaneous reads of the login Keychain), and overlapping reads are the
/// normal case here: the hook fires on both `PreToolUse` and `PostToolUse`.
///
/// The primitive has to match `filelock`'s: `fcntl.flock(fd, LOCK_EX | LOCK_NB)`
/// on unix — POSIX `fcntl(F_SETLK)` record locks would not exclude it on Linux —
/// and `msvcrt.locking(fd, LK_NBLCK, 1)`, the first-byte exclusive range
/// `LockFileEx` takes below, on Windows.
#[must_use = "the lock is held only while the returned file is alive"]
fn keyring_lock(timeout: Duration) -> Option<std::fs::File> {
    let dir = cache_dir()?;
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join(KEYRING_LOCK_FILENAME);
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(file) = try_keyring_lock(&path) {
            return Some(file);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(KEYRING_LOCK_POLL);
    }
}

/// One non-blocking attempt. `None` means "held by somebody else, or worth
/// retrying"; the caller owns the deadline.
fn try_keyring_lock(path: &Path) -> Option<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        // A symlink is not a lock file we or filelock would have made (filelock
        // passes O_NOFOLLOW too).
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).ok()?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `file` owns a live descriptor for the whole call, and flock
        // only ever inspects it.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return None;
        }
        // filelock unlinks the lock file as it releases it, so the inode we just
        // locked may already be detached from the path, where it excludes nobody.
        if file.metadata().ok()?.nlink() == 0 {
            return None;
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        // SAFETY: a live handle, and an OVERLAPPED that outlives the call.
        // `LOCKFILE_FAIL_IMMEDIATELY` is the non-blocking form, and one byte at
        // offset 0 is the region `msvcrt.locking(fd, LK_NBLCK, 1)` takes.
        let locked = unsafe {
            LockFileEx(
                file.as_raw_handle() as _,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut overlapped,
            )
        };
        if locked == 0 {
            return None;
        }
    }
    Some(file)
}

/// The token for `instance_url`, read from the OS credential store under
/// `token_store.py`'s lock. The lock covers the credential-store call and nothing
/// else; closing the file releases it, on every path out.
fn keyring_token(instance_url: &str) -> Result<String, Error> {
    // Bound to a name on purpose: `let _ = ` would release the lock before the
    // read it is meant to serialise.
    let _lock = keyring_lock(KEYRING_LOCK_TIMEOUT);
    read_credential_store(instance_url)
}

#[cfg(target_os = "macos")]
fn read_credential_store(instance_url: &str) -> Result<String, Error> {
    // Read only: a write probe is what popped blocking Keychain modals in Python.
    let raw = security_framework::passwords::get_generic_password(KEYRING_SERVICE, instance_url)
        .map_err(|_| Error::auth())?;
    String::from_utf8(raw).map_err(|_| Error::auth())
}

#[cfg(target_os = "linux")]
fn read_credential_store(instance_url: &str) -> Result<String, Error> {
    // keyring's SecretService backend looks an item up by the default scheme's
    // two attributes, `service` and `username` (backend.py:280-299,
    // SecretService.py:get_password), and token_store.py stores the token under
    // service == KEYRING_SERVICE, username == the instance URL. Query the same
    // attributes so we read the item keyring wrote and no other.
    let service = SecretService::connect(EncryptionType::Dh).map_err(|_| Error::auth())?;
    let attributes = HashMap::from([("service", KEYRING_SERVICE), ("username", instance_url)]);
    let found = service
        .search_items(attributes)
        .map_err(|_| Error::auth())?;
    // Prefer an already-unlocked item (keyring returns the first match); fall
    // back to a locked one, letting the daemon decide whether reading it needs a
    // prompt, mirroring keyring's own `unlock(); get_secret()`.
    let item = found
        .unlocked
        .into_iter()
        .chain(found.locked)
        .next()
        .ok_or_else(Error::auth)?;
    let secret = item.get_secret().map_err(|_| Error::auth())?;
    String::from_utf8(secret).map_err(|_| Error::auth())
}

#[cfg(windows)]
fn read_credential_store(instance_url: &str) -> Result<String, Error> {
    // keyring's WinVaultKeyring stores the token under TargetName == the service,
    // and only moves it to the compound target (username, '@', service) when a
    // second user collides on that service (Windows.py: _compound_name,
    // _resolve_credential). So: the service target first, accepted only when its
    // UserName matches, else the compound one. The blob is UTF-16.
    let service = KEYRING_SERVICE;
    if let Some((user, token)) = cred_read(service)?
        && user == instance_url
    {
        return Ok(token);
    }
    let compound = compound_target(instance_url, service);
    match cred_read(&compound)? {
        Some((_, token)) => Ok(token),
        None => Err(Error::auth()),
    }
}

/// WinVaultKeyring's `_compound_name(username, service)`: the username, a literal
/// `@`, then the service.
#[cfg(windows)]
fn compound_target(username: &str, service: &str) -> String {
    let mut target = String::with_capacity(username.len() + service.len() + 1);
    target.push_str(username);
    target.push('@');
    target.push_str(service);
    target
}

/// `CredReadW(CRED_TYPE_GENERIC)` for one target name, decoded exactly as
/// keyring's `DecodingCredential` does. Returns `(UserName, secret)` or `None`
/// when there is no such credential; any other failure is an auth fail-open.
#[cfg(windows)]
fn cred_read(target: &str) -> Result<Option<(String, String)>, Error> {
    // NUL-terminated UTF-16, as CredReadW's PCWSTR expects.
    let wide: Vec<u16> = std::ffi::OsStr::new(target)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: `wide` is a valid NUL-terminated buffer that outlives the call, and
    // `cred` is a valid out-pointer. On success CredReadW allocates a buffer we
    // free with CredFree below; on failure it writes nothing.
    let ok = unsafe { CredReadW(wide.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) };
    if ok == 0 {
        // SAFETY: reading a thread-local error code, no invariants.
        let err = unsafe { GetLastError() };
        return if err == ERROR_NOT_FOUND {
            Ok(None)
        } else {
            Err(Error::auth())
        };
    }

    // SAFETY: CredReadW reported success, so `cred` points at an initialized
    // CREDENTIALW whose blob/username fields we only read, then free.
    let result = unsafe {
        let c = &*cred;
        let blob = std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize);
        let token = decode_utf16le(blob);
        let user = if c.UserName.is_null() {
            String::new()
        } else {
            wide_to_string(c.UserName)
        };
        (user, token)
    };
    // SAFETY: `cred` was allocated by CredReadW and has not been freed yet.
    unsafe { CredFree(cred as *const _) };
    Ok(Some(result))
}

/// keyring writes the blob as UTF-16 (`DecodingCredential.value` does
/// `cred.decode('utf-16')`): honour an optional BOM, else little-endian.
#[cfg(windows)]
fn decode_utf16le(bytes: &[u8]) -> String {
    let (bytes, big_endian) = match bytes {
        [0xFF, 0xFE, rest @ ..] => (rest, false),
        [0xFE, 0xFF, rest @ ..] => (rest, true),
        _ => (bytes, false),
    };
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|p| {
            if big_endian {
                u16::from_be_bytes([p[0], p[1]])
            } else {
                u16::from_le_bytes([p[0], p[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

/// Read a NUL-terminated wide C string into a `String`.
#[cfg(windows)]
fn wide_to_string(ptr: *const u16) -> String {
    // SAFETY: caller guarantees `ptr` is a valid NUL-terminated UTF-16 string.
    unsafe {
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn read_credential_store(_instance_url: &str) -> Result<String, Error> {
    // No credential store implementation for this platform.
    Err(Error::unimplemented(
        "reading the token from this platform's credential store",
        "Set GITGUARDIAN_API_KEY in the environment.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Mutex, MutexGuard};

    /// The environment and the cwd are per-process, so tests touching them must
    /// not overlap.
    static PROCESS_STATE: Mutex<()> = Mutex::new(());

    fn exclusive() -> MutexGuard<'static, ()> {
        PROCESS_STATE.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// GIVEN a SaaS dashboard URL, with or without a trailing slash
    /// WHEN its API URL is derived
    /// THEN only the host label changes: `dashboard` becomes `api`, no path is added.
    #[test]
    fn saas_urls_swap_the_host_label() {
        assert_eq!(
            dashboard_to_api_url("https://dashboard.gitguardian.com"),
            "https://api.gitguardian.com"
        );
        assert_eq!(
            dashboard_to_api_url("https://dashboard-eu.gitguardian.com/"),
            "https://api-eu.gitguardian.com"
        );
    }

    /// GIVEN a self-hosted dashboard URL
    /// WHEN its API URL is derived
    /// THEN `/exposed` is appended, including for a gitguardian.com host that is
    /// not one of the SaaS dashboards.
    #[test]
    fn self_hosted_urls_get_the_exposed_prefix() {
        assert_eq!(
            dashboard_to_api_url("https://gg.example.com"),
            "https://gg.example.com/exposed"
        );
        assert_eq!(
            dashboard_to_api_url("https://onprem.gitguardian.com"),
            "https://onprem.gitguardian.com/exposed"
        );
    }

    /// GIVEN a `GITGUARDIAN_API_URL`
    /// WHEN it makes the api -> dashboard -> api round trip Python performs
    /// THEN it lands on the path the instance actually serves. `http://localhost:8000`
    /// is addressed at `http://localhost:8000/exposed`.
    #[test]
    fn api_url_round_trip_matches_python() {
        let round_trip = |u: &str| dashboard_to_api_url(&api_to_dashboard_url(u));
        assert_eq!(
            round_trip("http://localhost:8000"),
            "http://localhost:8000/exposed"
        );
        assert_eq!(
            round_trip("https://onprem.example.com/exposed"),
            "https://onprem.example.com/exposed"
        );
        assert_eq!(
            round_trip("https://api.gitguardian.com"),
            "https://api.gitguardian.com"
        );
    }

    /// GIVEN a variable set both in the real environment and in a `.env`
    /// WHEN it is resolved
    /// THEN the `.env` wins, as `ggshield` loads the file with `override=True`.
    #[test]
    fn a_dotenv_value_overrides_the_real_environment() {
        let _guard = exclusive();
        // SAFETY: serialised by `exclusive()`, removed below.
        unsafe { std::env::set_var("GITGUARDIAN_API_KEY", "from-the-environment") };

        let dotenv = vec![(
            "GITGUARDIAN_API_KEY".to_string(),
            "from-the-dotenv".to_string(),
        )];
        assert_eq!(
            env_var(&dotenv, "GITGUARDIAN_API_KEY").as_deref(),
            Some("from-the-dotenv")
        );
        // ...and a variable the file does not bind still comes from the process.
        assert_eq!(
            env_var(&DotEnv::new(), "GITGUARDIAN_API_KEY").as_deref(),
            Some("from-the-environment")
        );

        unsafe { std::env::remove_var("GITGUARDIAN_API_KEY") };
    }

    /// A temporary git checkout — `root/.git` plus a `root/sub` working directory
    /// — with `files` written relative to `root`. Returns the tempdir (kept alive
    /// by the caller) and the original cwd.
    fn in_a_checkout(files: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let original = std::env::current_dir().expect("cwd");
        std::fs::create_dir(dir.path().join(".git")).expect("mkdir .git");
        std::fs::create_dir(dir.path().join("sub")).expect("mkdir sub");
        for (name, content) in files {
            std::fs::write(dir.path().join(name), content).expect("write");
        }
        std::env::set_current_dir(dir.path().join("sub")).expect("chdir");
        (dir, original)
    }

    /// The instance `dotenv_overrides()` resolves with `vars` exported, or `Err`
    /// with the decline message.
    fn resolved_instance(vars: &[(&str, &str)]) -> Result<String, String> {
        // SAFETY: every caller holds `exclusive()`, and the vars are cleared
        // before returning.
        unsafe {
            for (key, value) in vars {
                std::env::set_var(key, value);
            }
        }
        let resolved = dotenv_overrides()
            .and_then(|dotenv| instance_name(&UserConfig::default(), &dotenv))
            .map_err(|error| match error {
                Error::Fail(message)
                | Error::Fatal(message)
                | Error::Invalid(message)
                | Error::Unsupported(message) => message,
            });
        unsafe {
            for (key, _) in vars {
                std::env::remove_var(key);
            }
        }
        resolved
    }

    /// GIVEN an instance or API URL over cleartext http, and the loopback hosts
    /// Python exempts
    /// WHEN the instance is resolved
    /// THEN the cleartext ones are refused with `validate_instance_url()`'s message
    /// — the token and the scanned content would otherwise go out unencrypted —
    /// and a local instance still works.
    #[test]
    fn a_cleartext_instance_is_refused() {
        let _guard = exclusive();
        let (_dir, original) = in_a_checkout(&[]);

        for (vars, expected) in [
            (
                [("GITGUARDIAN_INSTANCE", "http://gg.example.com")],
                Some("Invalid scheme for dashboard URL 'http://gg.example.com', expected HTTPS"),
            ),
            (
                [("GITGUARDIAN_API_URL", "http://gg.example.com/exposed")],
                Some("Invalid scheme for API URL 'http://gg.example.com/exposed', expected HTTPS"),
            ),
            // A URL with no scheme at all is refused too, as `urlparse` gives it
            // neither a scheme nor a netloc.
            (
                [("GITGUARDIAN_INSTANCE", "gg.example.com")],
                Some("Invalid scheme for dashboard URL 'gg.example.com', expected HTTPS"),
            ),
            ([("GITGUARDIAN_INSTANCE", "https://gg.example.com")], None),
            // The loopback exemptions, including the API-URL one Python narrows
            // to `localhost`.
            ([("GITGUARDIAN_INSTANCE", "http://localhost:8000")], None),
            ([("GITGUARDIAN_INSTANCE", "http://127.0.0.1:8000")], None),
            ([("GITGUARDIAN_API_URL", "http://localhost:8000")], None),
            (
                [("GITGUARDIAN_API_URL", "http://127.0.0.1:8000")],
                Some("Invalid scheme for API URL 'http://127.0.0.1:8000', expected HTTPS"),
            ),
        ] {
            let resolved = resolved_instance(&vars);
            match expected {
                None => assert!(resolved.is_ok(), "{vars:?}: {resolved:?}"),
                Some(detail) => {
                    let Err(message) = &resolved else {
                        panic!("{vars:?} was accepted: {resolved:?}");
                    };
                    assert!(message.contains(detail), "{vars:?}: {message}");
                    assert!(message.contains("NOT scanned for secrets"), "{message}");
                }
            }
        }

        std::env::set_current_dir(original).expect("chdir back");
    }

    /// GIVEN a `.gitguardian.yaml` naming a cleartext instance, the one source that
    /// carries no check of its own
    /// WHEN the instance is validated
    /// THEN it is refused too, because `Config.api_url` validates again.
    #[test]
    fn a_cleartext_instance_from_the_user_config_is_refused() {
        let user = UserConfig {
            instance: Some("http://gg.example.com".to_string()),
            ..UserConfig::default()
        };
        let instance = instance_name(&user, &DotEnv::default()).expect("resolves");
        assert!(validate_dashboard_url(&instance).is_err());
        assert!(validate_dashboard_url("https://gg.example.com").is_ok());
    }

    /// GIVEN a `.env` in the cwd, at the repository root, or named by
    /// `GITGUARDIAN_DOTENV_PATH`
    /// WHEN the config is resolved
    /// THEN the one `ggshield` would read is used — explicit path, else cwd, else
    /// repository root — and `GITGUARDIAN_DONT_LOAD_ENV` skips the file.
    #[test]
    fn the_dotenv_is_found_where_the_cli_looks_for_it() {
        let _guard = exclusive();
        let (dir, original) = in_a_checkout(&[
            (".env", "GITGUARDIAN_INSTANCE=https://gitroot\n"),
            ("other.env", "GITGUARDIAN_INSTANCE=https://explicit\n"),
        ]);

        assert_eq!(resolved_instance(&[]), Ok("https://gitroot".to_string()));
        std::fs::write(
            dir.path().join("sub/.env"),
            "GITGUARDIAN_INSTANCE=https://cwd\n",
        )
        .expect("write");
        assert_eq!(resolved_instance(&[]), Ok("https://cwd".to_string()));
        assert_eq!(
            resolved_instance(&[(
                "GITGUARDIAN_DOTENV_PATH",
                dir.path().join("other.env").to_str().expect("utf-8"),
            )]),
            Ok("https://explicit".to_string())
        );
        assert_eq!(
            resolved_instance(&[
                ("GITGUARDIAN_DONT_LOAD_ENV", "1"),
                ("GITGUARDIAN_INSTANCE", "https://env"),
            ]),
            Ok("https://env".to_string())
        );
        // Falsy spellings leave loading enabled, so the file beats the exported
        // variable.
        assert_eq!(
            resolved_instance(&[
                ("GITGUARDIAN_DONT_LOAD_ENV", "0"),
                ("GITGUARDIAN_INSTANCE", "https://env"),
            ]),
            Ok("https://cwd".to_string())
        );

        std::env::set_current_dir(original).expect("chdir back");
    }

    /// GIVEN a `.env` line binding a tracked variable that `dotenvy` rejects
    /// WHEN the config is resolved
    /// THEN it declines, naming that variable and the file: guessing the instance
    /// or the token means posting to the wrong server.
    #[test]
    fn an_unparseable_tracked_binding_declines_and_names_the_variable() {
        let _guard = exclusive();
        let (dir, original) = in_a_checkout(&[]);

        for (content, var) in [
            ("GITGUARDIAN_API_KEY=\"a\\tb\"\n", "GITGUARDIAN_API_KEY"),
            ("GITGUARDIAN_API_KEY='unterminated\n", "GITGUARDIAN_API_KEY"),
            (
                "GITGUARDIAN_INSTANCE=https://x junk\n",
                "GITGUARDIAN_INSTANCE",
            ),
            // A rejected *second* binding: the CLI would apply it, so resolving
            // the earlier one is a wrong answer, not a partial one.
            (
                "GITGUARDIAN_INSTANCE=https://cwd\nGITGUARDIAN_INSTANCE=\"a\\tb\"\n",
                "GITGUARDIAN_INSTANCE",
            ),
        ] {
            std::fs::write(dir.path().join("sub/.env"), content).expect("write");
            let message = resolved_instance(&[("GITGUARDIAN_INSTANCE", "https://env")])
                .expect_err(content)
                .to_string();
            assert!(message.contains(var), "{content:?}: {message}");
            assert!(message.contains("NOT scanned"), "{content:?}: {message}");
        }

        std::env::set_current_dir(original).expect("chdir back");
    }

    /// GIVEN a `.env` whose rejected line binds some *other* project's variable
    /// WHEN the config is resolved
    /// THEN it does not decline, and the tracked bindings around it still apply.
    #[test]
    fn an_unparseable_untracked_binding_does_not_block() {
        let _guard = exclusive();
        let (dir, original) = in_a_checkout(&[]);

        for content in [
            "FOO=\"a\\tb\"\nGITGUARDIAN_INSTANCE=https://cwd\n",
            "FOO=bar baz\nGITGUARDIAN_INSTANCE=https://cwd\n",
            "GITGUARDIAN_INSTANCE=https://cwd\nFOO='unterminated\n",
        ] {
            std::fs::write(dir.path().join("sub/.env"), content).expect("write");
            assert_eq!(
                resolved_instance(&[("GITGUARDIAN_INSTANCE", "https://env")]),
                Ok("https://cwd".to_string()),
                "{content:?}"
            );
        }

        std::env::set_current_dir(original).expect("chdir back");
    }

    /// GIVEN a stored account expiry
    /// WHEN it is compared against now
    /// THEN an absent or empty value never expires, and a past or unparseable one
    /// does.
    #[test]
    fn expiry_comparison() {
        assert!(!is_expired(None));
        assert!(!is_expired(Some("")));
        assert!(!is_expired(Some("2999-01-01T00:00:00+00:00")));
        assert!(!is_expired(Some("2999-01-01T00:00:00Z")));
        assert!(is_expired(Some("2020-01-01T00:00:00+00:00")));
        assert!(is_expired(Some("soon")));
    }

    /// GIVEN ggshield's auth-check cache on disk
    /// WHEN the hook reads this instance's scan limits from it
    /// THEN a matching, unexpired entry answers, and anything else is a miss.
    #[test]
    fn the_auth_check_cache_answers_only_for_this_token_while_it_is_fresh() {
        let _guard = exclusive();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("auth_check.yaml");
        // SAFETY: serialised by `exclusive()`, removed below.
        unsafe { std::env::set_var("GG_CACHE_DIR", dir.path()) };

        let entry = |key_hash: &str, expires_at: i64| {
            format!(
                "key_hash: {key_hash}\nexpires_at: {expires_at}\nscopes: null\n\
                 secrets_engine_version: null\nmaximum_payload_size: 5242880\n\
                 secret_scan_preferences:\n  maximum_document_size: 524288\n  \
                 maximum_documents_per_scan: 4\n"
            )
        };
        let hash = sha256_hex("https://api.example.com\0token");
        std::fs::write(&path, entry(&hash, now_unix() + 300)).expect("write");
        let limits = cached_limits("https://api.example.com", "token").expect("hit");
        assert_eq!(limits.maximum_document_size, Some(524_288));
        assert_eq!(limits.maximum_documents_per_scan, Some(4));
        assert_eq!(limits.maximum_payload_size, Some(5_242_880));

        assert!(cached_limits("https://api.example.com", "other").is_none());
        std::fs::write(&path, entry(&hash, now_unix() - 1)).expect("write");
        assert!(cached_limits("https://api.example.com", "token").is_none());
        std::fs::write(&path, "not: [yaml\n").expect("write");
        assert!(cached_limits("https://api.example.com", "token").is_none());
        std::fs::remove_file(&path).expect("remove");
        assert!(cached_limits("https://api.example.com", "token").is_none());

        unsafe { std::env::remove_var("GG_CACHE_DIR") };
    }

    /// Point the cache dir at a throwaway directory for the duration of a test.
    fn with_cache_dir(dir: &tempfile::TempDir) {
        // SAFETY: every caller holds `exclusive()`.
        unsafe { std::env::set_var("GG_CACHE_DIR", dir.path()) };
    }

    fn entry_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join(LIMITS_FILENAME)
    }

    const SEEDED: Limits = Limits {
        maximum_document_size: 524_288,
        maximum_documents_per_scan: 7,
        maximum_payload_size: 1_000_000,
    };

    /// Write an entry with a chosen age, to age it past the TTL or forge it into
    /// the future.
    fn seed_entry(dir: &tempfile::TempDir, api_url: &str, token: &str, age_seconds: i64) {
        let entry = LimitsCacheEntry {
            key: cache_key(api_url, token),
            stored_at: now_unix() - age_seconds,
            limits: SEEDED,
        };
        std::fs::write(
            entry_path(dir),
            serde_json::to_string(&entry).expect("json"),
        )
        .expect("write");
    }

    /// GIVEN limits this hook fetched and stored
    /// WHEN they are read back
    /// THEN the same (instance, token) hits while fresh, and another token,
    /// another instance, an expired entry and a future-dated one are all misses.
    #[test]
    fn the_limits_cache_answers_only_for_this_instance_and_token_while_it_is_fresh() {
        let _guard = exclusive();
        let dir = tempfile::tempdir().expect("tempdir");
        with_cache_dir(&dir);

        store_instance_limits("https://api.example.com", "token", SEEDED);
        let hit = cached_instance_limits("https://api.example.com", "token").expect("hit");
        assert_eq!(hit.maximum_document_size, 524_288);
        assert_eq!(hit.maximum_documents_per_scan, 7);
        assert_eq!(hit.maximum_payload_size, 1_000_000);

        assert!(cached_instance_limits("https://api.example.com", "other").is_none());
        assert!(cached_instance_limits("https://api.other.com", "token").is_none());

        seed_entry(
            &dir,
            "https://api.example.com",
            "token",
            LIMITS_TTL_SECONDS - 1,
        );
        assert!(cached_instance_limits("https://api.example.com", "token").is_some());
        seed_entry(
            &dir,
            "https://api.example.com",
            "token",
            LIMITS_TTL_SECONDS + 1,
        );
        assert!(cached_instance_limits("https://api.example.com", "token").is_none());
        // Clock skew, or an entry forged never to expire.
        seed_entry(&dir, "https://api.example.com", "token", -60);
        assert!(cached_instance_limits("https://api.example.com", "token").is_none());

        unsafe { std::env::remove_var("GG_CACHE_DIR") };
    }

    /// GIVEN a limits cache file that is corrupt, truncated, foreign or carries a
    /// zero limit
    /// WHEN it is read
    /// THEN every case is a miss and none of them panics.
    #[test]
    fn a_corrupt_or_zeroed_limits_cache_is_a_miss() {
        let _guard = exclusive();
        let dir = tempfile::tempdir().expect("tempdir");
        with_cache_dir(&dir);

        let key = cache_key("https://api.example.com", "token");
        let stored_at = now_unix();
        let truncated = {
            let mut raw = serde_json::to_string(&LimitsCacheEntry {
                key: key.clone(),
                stored_at,
                limits: SEEDED,
            })
            .expect("json");
            raw.truncate(raw.len() / 2);
            raw
        };
        for content in [
            String::new(),
            "not json".to_string(),
            "[1, 2, 3]".to_string(),
            "{}".to_string(),
            truncated,
            // Shaped like ours, with somebody else's idea of a limit.
            format!(r#"{{"key": "{key}", "stored_at": {stored_at}, "limits": "large"}}"#),
            // A zero is not a limit.
            format!(
                r#"{{"key": "{key}", "stored_at": {stored_at}, "limits": {{"maximum_document_size": 0, "maximum_documents_per_scan": 7, "maximum_payload_size": 1000}}}}"#
            ),
            format!(
                r#"{{"key": "{key}", "stored_at": {stored_at}, "limits": {{"maximum_document_size": 10, "maximum_documents_per_scan": 0, "maximum_payload_size": 1000}}}}"#
            ),
        ] {
            std::fs::write(entry_path(&dir), &content).expect("write");
            assert!(
                cached_instance_limits("https://api.example.com", "token").is_none(),
                "{content:?} must not be trusted"
            );
        }
        std::fs::remove_file(entry_path(&dir)).expect("remove");
        assert!(cached_instance_limits("https://api.example.com", "token").is_none());

        unsafe { std::env::remove_var("GG_CACHE_DIR") };
    }

    /// GIVEN a limits cache file another local user could have written, or a
    /// symlink standing in for one
    /// WHEN it is read
    /// THEN it is refused, and the next write repairs its permissions to 0600.
    #[cfg(unix)]
    #[test]
    fn a_group_or_other_writable_or_symlinked_limits_cache_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = exclusive();
        let dir = tempfile::tempdir().expect("tempdir");
        with_cache_dir(&dir);

        store_instance_limits("https://api.example.com", "token", SEEDED);
        let mode = std::fs::metadata(entry_path(&dir))
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "a fetched entry must not be readable");

        for mode in [0o660, 0o606, 0o666] {
            std::fs::set_permissions(entry_path(&dir), std::fs::Permissions::from_mode(mode))
                .expect("chmod");
            assert!(
                cached_instance_limits("https://api.example.com", "token").is_none(),
                "{mode:o} must not be trusted"
            );
        }
        store_instance_limits("https://api.example.com", "token", SEEDED);
        assert!(cached_instance_limits("https://api.example.com", "token").is_some());

        let elsewhere = dir.path().join("elsewhere.json");
        std::fs::rename(entry_path(&dir), &elsewhere).expect("rename");
        std::os::unix::fs::symlink(&elsewhere, entry_path(&dir)).expect("symlink");
        assert!(cached_instance_limits("https://api.example.com", "token").is_none());

        // The write replaces the symlink rather than writing through it.
        store_instance_limits("https://api.example.com", "token", SEEDED);
        assert!(cached_instance_limits("https://api.example.com", "token").is_some());
        assert!(
            !std::fs::symlink_metadata(entry_path(&dir))
                .expect("stat")
                .file_type()
                .is_symlink()
        );

        unsafe { std::env::remove_var("GG_CACHE_DIR") };
    }

    /// GIVEN a stored limits entry
    /// WHEN the write finishes
    /// THEN the cache directory holds only the entry: the temp file it was staged
    /// in was renamed over the target, so a concurrent run cannot read half of it.
    #[test]
    fn the_limits_cache_write_leaves_no_temp_file_behind() {
        let _guard = exclusive();
        let dir = tempfile::tempdir().expect("tempdir");
        with_cache_dir(&dir);

        store_instance_limits("https://api.example.com", "token", SEEDED);
        store_instance_limits("https://api.example.com", "token", SEEDED);
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, [LIMITS_FILENAME]);

        unsafe { std::env::remove_var("GG_CACHE_DIR") };
    }

    /// GIVEN an auth_config.yaml holding a plain token
    /// WHEN the token source is resolved
    /// THEN it is used as-is, without consulting the credential store.
    #[test]
    fn yaml_token_is_used_directly_when_it_is_not_the_sentinel() {
        let _guard = exclusive();
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("auth_config.yaml"),
            "instances:\n- url: https://dashboard.gitguardian.com\n  name: null\n  accounts:\n  \
             - token: real-token-value\n    expire_at: null\n",
        )
        .expect("write");
        // SAFETY: single-threaded test, restored immediately after.
        unsafe { std::env::set_var("GG_CONFIG_DIR", dir.path()) };
        let source = token_source_for_instance(DEFAULT_INSTANCE_URL).expect("resolves");
        unsafe { std::env::remove_var("GG_CONFIG_DIR") };
        let TokenSource::Plain(token) = source else {
            panic!("a plain YAML token must not be looked up in the credential store");
        };
        assert_eq!(token, "real-token-value");
    }

    /// GIVEN an auth_config.yaml holding the keyring sentinel
    /// WHEN the token source is resolved
    /// THEN it defers to the credential store instead of reading it now.
    #[test]
    fn sentinel_token_defers_to_the_credential_store() {
        let _guard = exclusive();
        let source = with_sentinel_config(|| token_source_for_instance("https://example.invalid"))
            .expect("resolves");
        match source {
            TokenSource::Keyring(url) => assert_eq!(url, "https://example.invalid"),
            TokenSource::Plain(token) => panic!("read the store eagerly, got {token:?}"),
        }
    }

    /// GIVEN `GGSHIELD_NO_KEYRING` is set
    /// WHEN the sentinel token is resolved
    /// THEN auth fails without touching the credential store, as Python's
    /// FileTokenStore does (it cannot hydrate the sentinel).
    #[test]
    fn no_keyring_env_var_fails_auth_without_touching_the_store() {
        let _guard = exclusive();
        for value in ["1", "true", "TRUE", "yes", ""] {
            // SAFETY: single-threaded test section, guarded by `exclusive()`.
            unsafe { std::env::set_var("GGSHIELD_NO_KEYRING", value) };
            let result =
                with_sentinel_config(|| token_source_for_instance("https://example.invalid"));
            unsafe { std::env::remove_var("GGSHIELD_NO_KEYRING") };
            let Err(Error::Fail(msg)) = result else {
                panic!("{value:?} must disable the keyring, got {result:?}");
            };
            assert!(msg.contains("could not authenticate"), "{msg}");
        }
        for value in ["0", "false", "False"] {
            unsafe { std::env::set_var("GGSHIELD_NO_KEYRING", value) };
            let result =
                with_sentinel_config(|| token_source_for_instance("https://example.invalid"));
            unsafe { std::env::remove_var("GGSHIELD_NO_KEYRING") };
            assert!(
                matches!(result, Ok(TokenSource::Keyring(_))),
                "{value:?} must leave the keyring enabled, got {result:?}"
            );
        }
    }

    /// Run `body` against a throwaway config dir whose only instance stores its
    /// token in the credential store.
    fn with_sentinel_config<T>(body: impl FnOnce() -> T) -> T {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("auth_config.yaml"),
            format!(
                "instances:\n- url: https://example.invalid\n  accounts:\n  - token: {KEYRING_SENTINEL}\n"
            ),
        )
        .expect("write");
        // SAFETY: callers hold `exclusive()`, so no other test reads the env.
        unsafe { std::env::set_var("GG_CONFIG_DIR", dir.path()) };
        let result = body();
        unsafe { std::env::remove_var("GG_CONFIG_DIR") };
        result
    }

    /// GIVEN an auth config whose only account expired in the past
    /// WHEN its token is read
    /// THEN it fails open with a "could not authenticate" warning.
    #[test]
    fn expired_account_fails_open_with_an_auth_warning() {
        let _guard = exclusive();
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("auth_config.yaml"),
            "instances:\n- url: https://example.invalid\n  accounts:\n  - token: t\n    \
             expire_at: '2020-01-01T00:00:00+00:00'\n",
        )
        .expect("write");
        unsafe { std::env::set_var("GG_CONFIG_DIR", dir.path()) };
        let result = token_source_for_instance("https://example.invalid");
        unsafe { std::env::remove_var("GG_CONFIG_DIR") };
        let Err(Error::Fail(msg)) = result else {
            panic!("expected a fail-open auth warning");
        };
        assert!(msg.contains("could not authenticate"), "{msg}");
    }

    /// GIVEN an instance with no item in the credential store
    /// WHEN its token is read
    /// THEN every platform fails open with an auth warning, never a panic. This is
    /// the branch the cross-OS CI matrix exercises without seeding a real secret.
    #[test]
    fn keyring_read_of_an_absent_item_fails_open() {
        let _guard = exclusive();
        // Own cache dir: the read takes the keyring lock.
        let dir = tempfile::tempdir().expect("tempdir");
        with_cache_dir(&dir);
        let result = keyring_token("https://keyring-absent.invalid");
        unsafe { std::env::remove_var("GG_CACHE_DIR") };
        assert!(
            matches!(result, Err(Error::Fail(_))),
            "an absent keyring item must fail open, got {result:?}"
        );
    }

    /// GIVEN a token that lives in the credential store, and no item to find
    /// WHEN both call sites that need it ask
    /// THEN the store is read once: the failure is memoised too, so a lock
    /// somebody else holds costs one timeout for the process, not one per call.
    #[test]
    fn a_failed_credential_store_read_is_not_repeated() {
        let _guard = exclusive();
        let dir = tempfile::tempdir().expect("tempdir");
        with_cache_dir(&dir);

        let config = Config {
            api_url: String::new(),
            token_source: TokenSource::Keyring("https://keyring-absent.invalid".into()),
            token: OnceCell::new(),
            user: UserConfig::default(),
            limits: OnceCell::new(),
        };
        assert!(config.token().is_err());
        assert!(
            config.token.get().is_some(),
            "the failed read was not memoised, so the next caller repeats it"
        );
        assert!(config.token().is_err());

        unsafe { std::env::remove_var("GG_CACHE_DIR") };
    }

    /// GIVEN two overlapping credential-store reads
    /// WHEN both take the keyring lock
    /// THEN their critical sections do not interleave, so securityd never sees the
    /// simultaneous Keychain reads it rejects.
    #[test]
    fn concurrent_keyring_reads_are_serialised() {
        let _guard = exclusive();
        let dir = tempfile::tempdir().expect("tempdir");
        with_cache_dir(&dir);

        let spans = Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(|| {
                    let lock = keyring_lock(Duration::from_secs(5)).expect("lock");
                    let entered = Instant::now();
                    std::thread::sleep(Duration::from_millis(150));
                    let left = Instant::now();
                    drop(lock);
                    spans.lock().expect("poisoned").push((entered, left));
                });
            }
        });

        let mut spans = spans.into_inner().expect("poisoned");
        assert_eq!(spans.len(), 2);
        spans.sort();
        assert!(
            spans[0].1 <= spans[1].0,
            "the two reads overlapped: {spans:?}"
        );
        unsafe { std::env::remove_var("GG_CACHE_DIR") };
    }

    /// GIVEN a lock somebody else holds for longer than the timeout
    /// WHEN a read waits for it
    /// THEN the wait ends at the timeout and the read proceeds unlocked: a hook
    /// that hangs blocks the agent.
    #[test]
    fn a_lock_held_past_the_timeout_does_not_hang_the_read() {
        let _guard = exclusive();
        let dir = tempfile::tempdir().expect("tempdir");
        with_cache_dir(&dir);

        // flock(2) is per open file description, so a second descriptor contends
        // even in-process.
        let held = keyring_lock(Duration::ZERO).expect("lock");
        let timeout = Duration::from_millis(300);
        let start = Instant::now();
        assert!(keyring_lock(timeout).is_none(), "took a held lock");
        let waited = start.elapsed();
        assert!(waited >= timeout, "gave up early, after {waited:?}");
        assert!(waited < timeout * 10, "waited past the timeout: {waited:?}");

        let result = keyring_token("https://keyring-absent.invalid");
        assert!(matches!(result, Err(Error::Fail(_))), "{result:?}");

        drop(held);
        unsafe { std::env::remove_var("GG_CACHE_DIR") };
    }

    /// GIVEN a cache directory that cannot be created
    /// WHEN the token is read
    /// THEN it is read unlocked instead of failing, and without burning the
    /// timeout first.
    #[cfg(unix)]
    #[test]
    fn an_unwritable_cache_dir_reads_unlocked() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = exclusive();
        let parent = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o500))
            .expect("chmod");
        // SAFETY: serialised by `exclusive()`, removed below.
        unsafe { std::env::set_var("GG_CACHE_DIR", parent.path().join("cache")) };

        let start = Instant::now();
        let result = keyring_token("https://keyring-absent.invalid");
        let elapsed = start.elapsed();

        unsafe { std::env::remove_var("GG_CACHE_DIR") };
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        assert!(matches!(result, Err(Error::Fail(_))), "{result:?}");
        assert!(elapsed < KEYRING_LOCK_TIMEOUT, "it waited: {elapsed:?}");
    }

    /// GIVEN a credential-store read that fails — no item for this instance
    /// WHEN it returns its error
    /// THEN the lock has already been released, so the next read does not wait.
    #[test]
    fn the_lock_is_released_when_the_read_fails() {
        let _guard = exclusive();
        let dir = tempfile::tempdir().expect("tempdir");
        with_cache_dir(&dir);

        let result = keyring_token("https://keyring-absent.invalid");
        assert!(matches!(result, Err(Error::Fail(_))), "{result:?}");
        assert!(
            keyring_lock(Duration::ZERO).is_some(),
            "the guard outlived the failed read"
        );

        unsafe { std::env::remove_var("GG_CACHE_DIR") };
    }

    /// GIVEN `filelock` holding `keyring.lock` from another process
    /// WHEN the Rust side takes the same lock
    /// THEN it waits for Python to release it: the two implementations exclude
    /// each other, not merely their own kind.
    ///
    /// Skipped when no interpreter with `filelock` is available.
    #[test]
    fn a_lock_held_by_python_filelock_blocks_the_rust_read() {
        let _guard = exclusive();
        let dir = tempfile::tempdir().expect("tempdir");
        with_cache_dir(&dir);
        let path = dir.path().join(KEYRING_LOCK_FILENAME);
        let hold = Duration::from_millis(1500);

        let python =
            std::env::var("GGSHIELD_VENV_PYTHON").unwrap_or_else(|_| "python3".to_string());
        let child = std::process::Command::new(python)
            .arg("-c")
            .arg(
                // Written to the binary buffer: on Windows the text layer would
                // turn "\n" into "\r\n" and desync the handshake below.
                "import sys, time, filelock\n\
                 with filelock.FileLock(sys.argv[1], timeout=10):\n\
                 \x20   sys.stdout.buffer.write(b'held\\n')\n\
                 \x20   sys.stdout.buffer.flush()\n\
                 \x20   time.sleep(float(sys.argv[2]))\n",
            )
            .arg(&path)
            .arg(hold.as_secs_f64().to_string())
            .stdout(std::process::Stdio::piped())
            .spawn();
        let Ok(mut child) = child else {
            unsafe { std::env::remove_var("GG_CACHE_DIR") };
            eprintln!("skipped: no python3");
            return;
        };
        use std::io::Read;
        let mut ready = [0u8; 5];
        let held_by_python = child
            .stdout
            .as_mut()
            .expect("piped")
            .read_exact(&mut ready)
            .is_ok();
        let start = Instant::now();
        let lock = keyring_lock(KEYRING_LOCK_TIMEOUT);
        let waited = start.elapsed();
        let acquired = lock.is_some();
        let _ = child.wait();
        drop(lock);
        unsafe { std::env::remove_var("GG_CACHE_DIR") };

        if !held_by_python {
            eprintln!("skipped: python3 cannot import filelock");
            return;
        }
        assert_eq!(&ready, b"held\n");
        assert!(acquired, "the lock was never taken, after {waited:?}");
        assert!(
            waited > hold - Duration::from_millis(300),
            "did not wait for python's lock, only {waited:?}"
        );
    }
}
