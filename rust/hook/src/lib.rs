//! The hook: `ggshield secret scan ai-hook`, as a library.
//!
//! The dispatcher binary (`../dispatcher`) is the `ggshield` the standalone
//! bundle puts on the PATH. It calls [`run_hook`] for the exact
//! `secret scan ai-hook` argv and hands everything else to `ggshield-py`, so
//! stdin is still untouched when we get here.
//!
//! Same job as the Python command: read a hook event on stdin, decide what to
//! scan, ask GitGuardian, print the agent's verdict JSON, exit 0. Detection is
//! server-side, so this is transport and glue — no rules live here.
//!
//! Anything this binary cannot reproduce declines and fails open with a warning
//! rather than guessing — see `config::dotenv_overrides()` and `user_config`.

mod api;
mod message;
mod notify;
mod output;
mod payload;
mod verdict_cache;

use ggshield_common::{binary_extensions, error};
use ggshield_config::config;
use ggshield_discovery::Inventory;

use std::io::Read;
use std::path::Path;

use error::Error;
use output::HookResult;
use payload::{EventType, Payload, Tool};

/// `MAX_READ_SIZE` in ai_hook.py.
const MAX_READ_SIZE: u64 = 10 * 1024 * 1024;

/// What the dispatcher must do once the hook has run.
pub enum Outcome {
    /// The event was handled — answered on stdout — and this is the exit code.
    Done(i32),
    /// A configuration the native hook knowingly does not implement: nothing has
    /// been printed and nothing decided, so `ggshield-py` must answer instead.
    ///
    /// `stdin` is the payload already read here, which the child cannot read
    /// again; `fallback_warning` is used only if handing over is impossible.
    Delegate {
        stdin: String,
        fallback_warning: Error,
    },
}

/// Run the hook end to end; the dispatcher acts on the outcome.
pub fn run_hook() -> Outcome {
    let mut buffer = Vec::new();
    let _ = std::io::stdin()
        .lock()
        .take(MAX_READ_SIZE)
        .read_to_end(&mut buffer);
    let stdin_content = String::from_utf8_lossy(&buffer).trim().to_string();

    // An agent reads a non-zero exit with no JSON as "the hook is broken", so a
    // panic is treated as any other internal failure.
    let outcome = std::panic::catch_unwind(|| run(&stdin_content))
        .unwrap_or_else(|_| Err(Error::scan("internal error")));

    match outcome {
        Ok(code) => Outcome::Done(code),
        // Nothing has been written to stdout yet on this path, so the child owns
        // the whole answer: no double verdict, no half-printed JSON.
        Err(err @ Error::Unsupported(_)) => Outcome::Delegate {
            stdin: stdin_content,
            fallback_warning: err,
        },
        Err(err) => Outcome::Done(handle_error(&stdin_content, err)),
    }
}

/// Fail open after a hand-over to `ggshield-py` could not happen. Separate from
/// `run_hook` because only the dispatcher knows whether it worked.
pub fn fail_open(stdin_content: &str, warning: Error) -> i32 {
    handle_error(stdin_content, warning)
}

/// Raise one harmless notification, so whatever the desktop wants to ask about
/// notifications gets asked now.
///
/// On macOS that is a permission prompt, and it is the whole point: an app may
/// only post notifications the user has allowed, and until the prompt is
/// answered `display notification` reports success and shows nothing. Asked
/// here, during `machine setup`, the user is deliberately setting ggshield up
/// and the dialog makes sense. Left to the first real detection, it lands on
/// top of a leaked secret -- and a prompt nobody answers is a leak alert
/// nobody sees.
///
/// Always exits 0: an installer must not fail over a banner.
pub fn warm_notifier() -> i32 {
    notify::send(
        "ggshield",
        "ggshield will alert you here when a secret reaches your AI agent.",
    );
    0
}

/// The three failure modes of `ai_hook_cmd`.
fn handle_error(stdin_content: &str, err: Error) -> i32 {
    let warning = match err {
        // `except ValueError`: stderr, exit 1, nothing on stdout.
        Error::Invalid(message) => {
            eprintln!("{message}");
            return 1;
        }
        // Raised while loading config, before the command's try block exists:
        // ExitCode.UNEXPECTED_ERROR, no fail-open.
        Error::Fatal(message) => {
            eprintln!("Error: {message}");
            return 128;
        }
        // Only reached when the dispatcher could not hand this event to
        // `ggshield-py`; it then behaves exactly like any other fail-open.
        Error::Fail(warning) | Error::Unsupported(warning) => warning,
    };

    // `emit_fail_open_response()`: warn, then allow *with* the warning attached
    // so the user learns the action went unscanned.
    eprintln!("Warning: {warning}");
    match payload::parse(stdin_content) {
        // We cannot tell who is calling, so no well-formed response is possible.
        // Agents treat exit 1 as a non-blocking error.
        Err(_) => 1,
        Ok(payloads) => match payloads.last() {
            None => 1,
            Some(payload) => {
                output::output_result(&HookResult::allow_with_warning(payload, warning))
            }
        },
    }
}

fn run(stdin_content: &str) -> Result<i32, Error> {
    // Config before the debounce, as in Python: a broken config must fail open
    // even for a duplicate payload. The credential-store read is deferred, see
    // `Config::token`.
    let config = config::resolve()?;
    warn_if_insecure(&config);
    let exit_zero = config.user.exit_zero;
    Ok(apply_exit_zero(scan(&config, stdin_content)?, exit_zero))
}

/// The two warnings `create_session()` prints when TLS verification is disabled.
/// They go to stderr, so the verdict on stdout is unaffected.
fn warn_if_insecure(config: &config::Config) {
    if !config.user.insecure {
        return;
    }
    eprintln!(
        "Warning: SSL verification is disabled. Your connection to the GitGuardian API is NOT \
         encrypted and is vulnerable to man-in-the-middle attacks. Traffic, including API keys \
         and scan results, can be intercepted and modified."
    );
    eprintln!(
        "Warning: To securely use self-signed certificates with Python >= 3.10, disable this \
         option and install your certificate in your system's trust store. See: \
         https://docs.gitguardian.com/ggshield-docs/configuration#support-for-self-signed-certificates"
    );
}

/// The `scan_group` result callback in `__main__.py`: with `exit_zero` set, an
/// exit code of SCAN_FOUND_PROBLEMS (1) is forced to 0.
fn apply_exit_zero(code: i32, exit_zero: bool) -> i32 {
    if exit_zero && code == 1 { 0 } else { code }
}

fn scan(config: &config::Config, stdin_content: &str) -> Result<i32, Error> {
    let mut payloads = payload::parse(stdin_content)?;

    // Before the debounce, not after: declining hands this same stdin to
    // `ggshield-py`, and a debounce entry we had already written would make it
    // exit 0 with no verdict at all — an allow nobody decided.
    let inventory = mcp_inventory(&payloads)?;

    if !stdin_content.is_empty() && has_already_been_seen(stdin_content) {
        return Ok(0);
    }

    let (index, verdict) = scan_payloads(config, &mut payloads, inventory.as_ref())?;
    let payload = &payloads[index];

    let result = match verdict {
        Verdict::Allowed => return Ok(output::output_result(&HookResult::allow(payload))),
        // Not a secret, so no count and no remediation steps: the reason is the
        // organisation's own, and it is shown as it was written.
        Verdict::NotPermitted(reason) => HookResult::block(payload, reason, 0),
        Verdict::Secrets(secrets) => HookResult::block(
            payload,
            message::from_secrets(&secrets, payload),
            secrets.len(),
        ),
    };
    // `has_secret_already_leaked()`: on PostToolUse the secret is already in the
    // agent's context, so tell the user out-of-band. Best effort.
    if payload.event_type == EventType::PostToolUse {
        notify(&result);
    }
    Ok(output::output_result(&result))
}

/// One payload still waiting for an API answer, and its cache key.
struct Pending {
    /// Index of the payload the document came from: the batch is not the payload
    /// list (empty, over-size and already-cached payloads are left out), so a
    /// position in the batch says nothing about a position in the event.
    index: usize,
    document: api::Document,
    /// The verdict-cache key, or `None` past the 1 MiB threshold, matching
    /// hooks.py, which keys the cache on empty content for those.
    key: Option<String>,
}

/// What the event is allowed to do, once both of the API's answers are in.
enum Verdict {
    Allowed,
    /// Secrets the scan found, which the block message is built from.
    Secrets(Vec<api::Secret>),
    /// The MCP activity endpoint refused this tool call, with the organisation's
    /// own reason. The arguments were clean; the call itself is denied.
    NotPermitted(String),
}

/// `_scan_payloads()` plus `_scan_contents()` and `_send_mcp_activity()`: settle
/// everything this event needs settled, in as few requests as possible.
///
/// Returns the verdict and the index of the payload it belongs to, or index 0 when
/// nothing blocks — the caller only reads that payload for its output contract.
///
/// An MCP tool call needs both of the API's answers: the arguments can carry a
/// secret, *and* the call itself can be one the organisation does not permit.
/// Neither implies the other.
///
/// Verdicts are applied one payload at a time, in the order the payloads were
/// parsed, and a scan verdict takes precedence over an activity verdict for the
/// same payload, exactly as in `_scan_payloads()`.
///
/// A chunk the API refused is reported — a fail-open `Err` — only when nothing
/// blocks: any verdict already settled outranks it, so a denial in hand is not
/// discarded by a later chunk that could not be scanned.
fn scan_payloads(
    config: &config::Config,
    payloads: &mut [Payload],
    inventory: Option<&Inventory>,
) -> Result<(usize, Verdict), Error> {
    if payloads.is_empty() {
        return Err(Error::Invalid("Error: no payloads to scan".into()));
    }
    let agent = payloads[0].agent;
    let denial = mcp_denial(config, payloads, inventory)?;

    let mut pending: Vec<Pending> = Vec::new();
    for (index, payload) in payloads.iter_mut().enumerate() {
        let Some((content, filename)) = scannable(config, payload) else {
            continue;
        };
        if content.is_empty() {
            continue;
        }
        // Over the instance's ceiling: skipped, as `_start_scans()` does.
        // Sending it anyway would earn a 400 and fail the whole event open.
        if content.len() > api::max_document_size(config) {
            continue;
        }

        // hooks.py keys the cache on empty content past
        // `DOCUMENT_SIZE_THRESHOLD_BYTES`, so a document over 1 MiB is scanned but
        // never cached, and the instance ceiling must not change that.
        let key = if content.len() <= config::MAXIMUM_DOCUMENT_SIZE {
            Some(verdict_cache::key(
                &config.api_url,
                config.token()?,
                &config.user.secret,
                &filename,
                &content,
            ))
        } else {
            None
        };
        // A Read resolves to the same document at PreToolUse and PostToolUse, so
        // the second event is answered locally. `has_already_been_seen()` cannot:
        // it debounces on raw stdin, which differs between the two.
        if let Some(key) = &key
            && verdict_cache::has_clean_verdict(key)
        {
            continue;
        }

        pending.push(Pending {
            index,
            document: api::Document { content, filename },
            key,
        });
    }
    if pending.is_empty() {
        return Ok(apply(None, denial));
    }

    let mut found: Option<(usize, Vec<api::Secret>)> = None;
    let mut failure: Option<Error> = None;
    let max_documents = api::max_documents_per_scan(config);
    let max_payload_size = api::max_payload_size(config);
    for chunk in chunks(&pending, max_documents, max_payload_size) {
        // `_collect_results()` reports a failed chunk and carries on with the
        // rest. Propagating here instead discarded every secret the earlier
        // chunks had already found and skipped the remaining ones — reachable
        // from a prompt mentioning 21 files.
        let results = match api::multiscan(config, agent, chunk.iter().map(|item| &item.document)) {
            Ok(results) => results,
            Err(error) => {
                failure = failure.or(Some(error));
                continue;
            }
        };
        // /v1/multiscan answers one result per document, in order. Any other
        // count is a degraded answer that cannot be attributed to a document.
        let unambiguous = results.len() == chunk.len();
        for (item, result) in chunk.iter().zip(results) {
            // `filtered_out` must be 0 too: an empty `secrets` can also mean the
            // API reported breaks this project's ignore rules dropped, and caching
            // that would let one project's rule allow content elsewhere.
            if unambiguous
                && result.secrets.is_empty()
                && result.filtered_out == 0
                && let Some(key) = &item.key
            {
                verdict_cache::store_clean_verdict(key);
            }
            if !result.secrets.is_empty() && found.is_none() {
                found = Some((item.index, result.secrets));
            }
        }
    }
    match apply(found, denial) {
        // Nothing to block on, but a chunk went unscanned: fail open with the
        // API's reason rather than report the event clean.
        (_, Verdict::Allowed) => match failure {
            Some(failure) => Err(failure),
            None => Ok((0, Verdict::Allowed)),
        },
        // A verdict beats a partial failure: blocking on what was settled is never
        // worse than failing the whole event open — and a denial already in hand
        // must not be thrown away by a later chunk the API refused.
        settled => Ok(settled),
    }
}

/// `_scan_payloads()`'s final loop: the earlier blocking index wins, and on the
/// same index the secret does.
fn apply(
    secrets: Option<(usize, Vec<api::Secret>)>,
    denial: Option<(usize, String)>,
) -> (usize, Verdict) {
    match (secrets, denial) {
        (Some((index, secrets)), None) => (index, Verdict::Secrets(secrets)),
        (None, Some((index, reason))) => (index, Verdict::NotPermitted(reason)),
        (Some((scanned, secrets)), Some((denied, reason))) => {
            if scanned <= denied {
                (scanned, Verdict::Secrets(secrets))
            } else {
                (denied, Verdict::NotPermitted(reason))
            }
        }
        (None, None) => (0, Verdict::Allowed),
    }
}

/// `is_mcp_activity_payload()`: only a `PreToolUse` on an MCP tool is activity.
/// There is nothing to permit or deny after the fact.
fn is_mcp_activity(payload: &Payload) -> bool {
    payload.event_type == EventType::PreToolUse && payload.tool == Some(Tool::Mcp)
}

/// The inventory this event's MCP payloads need, or a decline if there is none.
///
/// `refresh_and_maybe_submit_discovery()` in one line: a fresh `ai_discovery.json`
/// is trusted rather than re-walked. What this cannot do is *produce* one, so a
/// stale or absent file declines the whole event to `ggshield-py`, which owns the
/// walk — it then submits and rewrites the file, and the next hour runs natively.
///
/// Deliberately not a fail-open: allowing without an inventory would make deleting
/// one cache file enough to lift an administrator's block.
fn mcp_inventory(payloads: &[Payload]) -> Result<Option<Inventory>, Error> {
    if !payloads.iter().any(is_mcp_activity) {
        return Ok(None);
    }
    ggshield_discovery::load_fresh().map(Some).ok_or_else(|| {
        Error::unimplemented(
            "checking MCP tool calls against your organization's policies without a \
             recent inventory of your MCP servers",
            "Reinstall ggshield: the bundled Python implementation, which builds that \
             inventory, should sit next to the 'ggshield' executable.",
        )
    })
}

/// `send_mcp_activity()` for every MCP payload in the event, and the first denial
/// it comes back with.
///
/// Sequential with the scan, where Python overlaps the two on a thread pool:
/// `Config` memoises the token in a `OnceCell` and so is not `Sync`, and sharing
/// it across a scope would mean resolving the credential store up front — the one
/// call that can block on a macOS Keychain prompt.
fn mcp_denial(
    config: &config::Config,
    payloads: &[Payload],
    inventory: Option<&Inventory>,
) -> Result<Option<(usize, String)>, Error> {
    let Some(inventory) = inventory else {
        return Ok(None);
    };
    for (index, payload) in payloads.iter().enumerate() {
        if !is_mcp_activity(payload) {
            continue;
        }
        if let Some(reason) = api::mcp_activity(config, payload, inventory)? {
            return Ok(Some((index, reason)));
        }
    }
    Ok(None)
}

/// `_start_scans()`'s chunking: the API caps a scan both in documents and in
/// bytes, and going over either is a 400, i.e. a fail-open.
fn chunks(
    pending: &[Pending],
    max_documents: usize,
    max_payload_size: usize,
) -> impl Iterator<Item = &[Pending]> {
    let mut rest = pending;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let mut size = 0;
        let take = rest
            .iter()
            .take(max_documents)
            .take_while(|item| {
                size += item.document.content.len();
                size <= max_payload_size
            })
            .count()
            // A document that fits in no batch would otherwise loop forever.
            .max(1);
        let (chunk, tail) = rest.split_at(take);
        rest = tail;
        Some(chunk)
    })
}

/// `UTF8_TO_WORSE_OTHER_ENCODING_RATIO` in scannable.py: past this multiple of the
/// ceiling, no encoding could bring the file under it, so Python answers
/// `is_longer_than()` from the byte size and never reads the file.
const UTF8_TO_WORSE_OTHER_ENCODING_RATIO: u64 = 4;

/// For a Read tool pointing at a real, non-binary file the *file* is scanned,
/// not the payload text. Everything else scans the payload content under the
/// identifier as its filename.
///
/// `None` means "nothing to scan here": the file is too large to be scanned at
/// all, so reading it would only cost the memory.
fn scannable(config: &config::Config, payload: &mut Payload) -> Option<(String, String)> {
    if payload.tool == Some(Tool::Read) {
        let path = Path::new(&payload.identifier);
        if path.is_file() && !is_path_binary(path) {
            // Reading first and measuring after is how `@big.log` on a multi-GB
            // file became an OOM, i.e. no JSON and a non-zero exit: the agent
            // proceeds unscanned. A ranged read still reads, as Python does —
            // its slice can well be under the ceiling.
            if payload.read_range.is_none() && is_over_any_encoding_of_the_ceiling(config, path) {
                return None;
            }
            let content = decode(&std::fs::read(path).ok()?);
            // Only the lines the agent asked for reach the model, and sending
            // the whole file can push it over the document ceiling.
            let content = match payload.read_range {
                Some(range) => payload::line_slice(&content, range),
                None => content,
            };
            return Some((content, payload.identifier.clone()));
        }
    }
    Some((
        std::mem::take(&mut payload.content),
        payload.identifier.clone(),
    ))
}

fn is_over_any_encoding_of_the_ceiling(config: &config::Config, path: &Path) -> bool {
    let ceiling =
        (api::max_document_size(config) as u64).saturating_mul(UTF8_TO_WORSE_OTHER_ENCODING_RATIO);
    std::fs::metadata(path).is_ok_and(|meta| meta.len() > ceiling)
}

/// A file's bytes as text, honouring a byte-order mark.
///
/// `Scannable._decode_bytes()` decodes with charset_normalizer and
/// `errors="replace"`. Requiring strict UTF-8 instead would skip ordinary files
/// (PowerShell's `Out-File` writes UTF-16LE with a BOM), and a skipped file is an
/// *allowed* read — its secrets would reach the model unscanned. Lossy is safe
/// here because secrets are ASCII and ASCII survives every encoding below byte
/// for byte. Not covered: charset_normalizer's statistical detection of BOM-less
/// legacy encodings (CP1250 and friends), which decode as UTF-8.
fn decode(bytes: &[u8]) -> String {
    match bytes {
        // UTF-32 first: its LE mark starts with the whole UTF-16 LE mark.
        [0xFF, 0xFE, 0x00, 0x00, rest @ ..] => decode_utf32(rest, u32::from_le_bytes),
        [0x00, 0x00, 0xFE, 0xFF, rest @ ..] => decode_utf32(rest, u32::from_be_bytes),
        [0xFF, 0xFE, rest @ ..] => decode_utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => decode_utf16(rest, u16::from_be_bytes),
        // `bytes.decode()` does not drop the UTF-8 mark either, so Python strips
        // it by hand as well; left in, it would show up in the scanned text.
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8_lossy(rest).into_owned(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// A trailing odd byte is dropped: it cannot be part of a code unit.
fn decode_utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| unit([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

fn decode_utf32(bytes: &[u8], unit: fn([u8; 4]) -> u32) -> String {
    bytes
        .chunks_exact(4)
        .map(|quad| {
            char::from_u32(unit([quad[0], quad[1], quad[2], quad[3]]))
                .unwrap_or(char::REPLACEMENT_CHARACTER)
        })
        .collect()
}

/// `is_path_binary()`: extension test only, same list as ggshield.
fn is_path_binary(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| binary_extensions::BINARY_EXTENSIONS.contains(&ext))
}

/// `has_already_been_seen()`. Some setups install hooks from several assistants
/// and invoke us twice with an identical payload.
///
/// No file lock, unlike Python's `filelock`: losing the race means both
/// processes scan the same payload — slower, never less safe.
fn has_already_been_seen(content: &str) -> bool {
    let hash = payload::sha256_hex(content.trim());
    let Some(dir) = config::cache_dir() else {
        return false;
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return false;
    }
    let path = dir.join("latest_ai_hook.txt");
    let stored = std::fs::read_to_string(&path).unwrap_or_default();
    if stored == hash {
        return true;
    }
    let _ = std::fs::write(&path, &hash);
    false
}

/// `_send_secret_notification()`. Best effort; every failure is swallowed so the
/// block decision still gets emitted.
///
/// Only the wording lives here; `notify` owns the per-OS delivery.
fn notify(result: &HookResult) {
    let source = match result.payload.tool {
        Some(Tool::Read) => "reading a file".to_string(),
        Some(Tool::Bash) => {
            let command = result
                .payload
                .raw
                .get("tool_input")
                .and_then(|i| i.get("command"))
                .and_then(|c| c.as_str())
                .unwrap_or_default();
            if command.is_empty() {
                "running a command".to_string()
            } else {
                format!("running the command `{command}`")
            }
        }
        _ => "using a tool".to_string(),
    };
    let body = format!(
        "{} got access to {} {} by {source}",
        result.payload.agent.display_name(),
        result.nbr_secrets,
        message::pluralize("secret", result.nbr_secrets, None)
    );
    notify::send("ggshield - Secrets Detected", &body);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Recognised by the mock below as "this document holds a secret".
    const SECRET: &str = "AKIAsomething";

    /// How the mock answers: the limits it reports on `/v1/metadata`, which
    /// multiscan it refuses, and what the MCP activity endpoint says about the tool
    /// call — `None` permits it.
    #[derive(Clone, Copy)]
    struct Mock {
        max_documents_per_scan: usize,
        max_document_size: usize,
        /// The 0-based multiscan request that answers 400 instead of a verdict.
        fail_scan: Option<usize>,
        deny: Option<&'static str>,
    }

    impl Default for Mock {
        fn default() -> Self {
            Mock {
                max_documents_per_scan: config::DEFAULT_MAX_DOCUMENTS_PER_SCAN,
                max_document_size: config::MAXIMUM_DOCUMENT_SIZE,
                fail_scan: None,
                deny: None,
            }
        }
    }

    /// What the mock recorded: every multiscan batch's filenames, every MCP
    /// activity report, and how many times `/v1/metadata` was fetched.
    struct Recorded {
        batches: Mutex<Vec<Vec<String>>>,
        activities: Mutex<Vec<serde_json::Value>>,
        metadata_hits: AtomicUsize,
    }

    /// A localhost stand-in for the API: answers `/v1/metadata` (with the given
    /// limits), `/v1/multiscan` and `/v1/agent-activity/mcp-activity`, recording
    /// what it was sent. Nothing ever leaves the machine.
    fn mock_api(limits: Mock) -> (String, Arc<Recorded>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let recorded = Arc::new(Recorded {
            batches: Mutex::new(Vec::new()),
            activities: Mutex::new(Vec::new()),
            metadata_hits: AtomicUsize::new(0),
        });
        let served = Arc::clone(&recorded);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                serve(stream, &served, limits);
            }
        });
        (url, recorded)
    }

    /// One request: the metadata a client reads before chunking, the policy answer
    /// for an MCP tool call, or a multiscan answering — as the real one does —
    /// exactly one result per document, in the order the documents were sent.
    fn serve(mut stream: TcpStream, recorded: &Recorded, limits: Mock) {
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut request_line = String::new();
        reader.read_line(&mut request_line).expect("request line");
        let mut length = 0usize;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).expect("header") == 0 || header == "\r\n" {
                break;
            }
            if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse().unwrap_or(0);
            }
        }

        let body = if request_line.starts_with("GET") {
            recorded.metadata_hits.fetch_add(1, Ordering::SeqCst);
            let Mock {
                max_documents_per_scan,
                max_document_size,
                ..
            } = limits;
            format!(
                r#"{{"preferences": {{"general__maximum_payload_size": 2621440}}, "secret_scan_preferences": {{"maximum_document_size": {max_document_size}, "maximum_documents_per_scan": {max_documents_per_scan}}}}}"#
            )
        } else if request_line.contains("/v1/agent-activity/mcp-activity") {
            let mut raw = vec![0u8; length];
            reader.read_exact(&mut raw).expect("body");
            recorded
                .activities
                .lock()
                .expect("lock")
                .push(serde_json::from_slice(&raw).expect("activity"));
            match limits.deny {
                Some(reason) => json!({"allowed": false, "reason": reason}).to_string(),
                None => json!({"allowed": true, "reason": ""}).to_string(),
            }
        } else {
            let mut raw = vec![0u8; length];
            reader.read_exact(&mut raw).expect("body");
            let documents: Vec<serde_json::Value> =
                serde_json::from_slice(&raw).expect("documents");
            let mut batches = recorded.batches.lock().expect("lock");
            batches.push(
                documents
                    .iter()
                    .map(|d| d["filename"].as_str().unwrap_or_default().to_string())
                    .collect(),
            );
            let index = batches.len() - 1;
            drop(batches);
            if limits.fail_scan == Some(index) {
                const REFUSED: &str = r#"{"detail": "refused"}"#;
                let _ = write!(
                    stream,
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{REFUSED}",
                    REFUSED.len()
                );
                return;
            }
            let results: Vec<&str> = documents
                .iter()
                .map(|d| {
                    if d["document"].as_str().unwrap_or_default().contains(SECRET) {
                        r#"{"policy_breaks": [{"policy": "Secrets detection", "type": "AWS Keys",
                            "matches": [{"match": "AKIAsomething", "type": "apikey"}]}]}"#
                    } else {
                        r#"{"policy_breaks": []}"#
                    }
                })
                .collect();
            format!("[{}]", results.join(","))
        };
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
    }

    fn test_config(api_url: String) -> config::Config {
        config::Config::with_token(api_url, "token".into(), Default::default())
    }

    /// A config with no instance to reach, so `max_document_size` answers from the
    /// compiled-in default. Port 1 is unbound: connection refused, immediately.
    fn offline_config() -> config::Config {
        test_config("http://127.0.0.1:1".into())
    }

    /// `scan_payloads` for an event with no MCP payload in it, reduced to the
    /// secrets found — which is all the scan-side cases below assert on.
    fn scan_for_secrets(
        config: &config::Config,
        payloads: &mut [Payload],
    ) -> Result<(usize, Vec<api::Secret>), Error> {
        let (index, verdict) = scan_payloads(config, payloads, None)?;
        Ok((
            index,
            match verdict {
                Verdict::Secrets(secrets) => secrets,
                Verdict::Allowed | Verdict::NotPermitted(_) => Vec::new(),
            },
        ))
    }

    fn text_payload(identifier: &str, content: &str) -> Payload {
        Payload {
            event_type: EventType::UserPrompt,
            tool: None,
            content: content.into(),
            identifier: identifier.into(),
            agent: payload::Agent::Claude,
            raw: serde_json::Value::Object(Default::default()),
            read_range: None,
        }
    }

    /// GIVEN one event carrying an empty, a clean, a leaky and another clean payload
    /// WHEN it is scanned
    /// THEN it costs one multiscan request, and the secret is attributed to the
    /// payload holding it rather than to its position in the batch.
    #[test]
    fn one_event_is_one_request_and_the_block_lands_on_the_right_payload() {
        let (_guard, _dir) = verdict_cache::with_cache_dir();
        let (url, recorded) = mock_api(Mock::default());
        let mut payloads = [
            text_payload("empty.txt", ""),
            text_payload("clean.txt", "nothing here"),
            text_payload("leaky.txt", &format!("aws_key = {SECRET}")),
            text_payload("also-clean.txt", "nothing here either"),
        ];

        let (index, secrets) = scan_for_secrets(&test_config(url), &mut payloads).expect("scan");

        assert_eq!(index, 2);
        assert_eq!(secrets.len(), 1);
        let batches = recorded.batches.lock().expect("lock");
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0], ["clean.txt", "leaky.txt", "also-clean.txt"]);
        assert_eq!(recorded.metadata_hits.load(Ordering::SeqCst), 1);
    }

    /// GIVEN an instance reporting a raised `maximum_documents_per_scan`
    /// WHEN a larger batch is scanned
    /// THEN it is chunked to what the instance reports, not to the default.
    #[test]
    fn a_batch_over_the_limit_is_chunked_to_what_metadata_reports() {
        let (_guard, _dir) = verdict_cache::with_cache_dir();
        let (url, recorded) = mock_api(Mock {
            max_documents_per_scan: 8,
            ..Mock::default()
        });
        let mut payloads: Vec<Payload> = (0..21)
            .map(|i| text_payload(&format!("file{i}.txt"), &format!("content {i}")))
            .collect();

        let (_, secrets) = scan_for_secrets(&test_config(url), &mut payloads).expect("scan");

        assert!(secrets.is_empty());
        let batches = recorded.batches.lock().expect("lock");
        assert_eq!(batches.iter().map(Vec::len).collect::<Vec<_>>(), [8, 8, 5]);
        assert_eq!(batches.iter().flatten().count(), 21);
    }

    /// GIVEN an instance whose `maximum_documents_per_scan` is BELOW the default
    /// WHEN a batch larger than it is scanned
    /// THEN it is still chunked to the instance limit.
    #[test]
    fn a_batch_is_chunked_to_a_sub_default_instance_limit() {
        let (_guard, _dir) = verdict_cache::with_cache_dir();
        let (url, recorded) = mock_api(Mock {
            max_documents_per_scan: 3,
            ..Mock::default()
        });
        let mut payloads: Vec<Payload> = (0..8)
            .map(|i| text_payload(&format!("file{i}.txt"), &format!("content {i}")))
            .collect();

        let (_, secrets) = scan_for_secrets(&test_config(url), &mut payloads).expect("scan");

        assert!(secrets.is_empty());
        let batches = recorded.batches.lock().expect("lock");
        assert_eq!(batches.iter().map(Vec::len).collect::<Vec<_>>(), [3, 3, 2]);
    }

    /// GIVEN an instance whose `maximum_document_size` is raised above 1 MiB
    /// WHEN a ~2 MiB secret-bearing document is scanned
    /// THEN it reaches the API and blocks instead of being skipped.
    #[test]
    fn a_large_document_under_the_raised_instance_limit_is_scanned() {
        let (_guard, _dir) = verdict_cache::with_cache_dir();
        let (url, recorded) = mock_api(Mock {
            max_document_size: 4 * 1024 * 1024,
            ..Mock::default()
        });
        // Over the 1 MiB trigger, under the 4 MiB instance limit.
        let big = format!(
            "{}\n{SECRET}\n{}",
            "x".repeat(1_500_000),
            "y".repeat(600_000)
        );
        assert!(big.len() > config::MAXIMUM_DOCUMENT_SIZE);
        let mut payloads = [text_payload("big.txt", &big)];

        let (index, secrets) = scan_for_secrets(&test_config(url), &mut payloads).expect("scan");

        assert_eq!(index, 0);
        assert_eq!(secrets.len(), 1);
        let batches = recorded.batches.lock().expect("lock");
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0], ["big.txt"]);
        assert_eq!(recorded.metadata_hits.load(Ordering::SeqCst), 1);
    }

    /// GIVEN an instance whose `maximum_document_size` is BELOW the compiled-in
    /// 1 MiB default
    /// WHEN a document over the instance limit but under 1 MiB is scanned
    /// THEN it is skipped rather than sent, where a 400 would fail the event open.
    #[test]
    fn a_document_over_a_sub_default_instance_limit_is_skipped() {
        let (_guard, _dir) = verdict_cache::with_cache_dir();
        let (url, recorded) = mock_api(Mock {
            max_document_size: 512 * 1024,
            ..Mock::default()
        });
        let big = format!("{SECRET}\n{}", "x".repeat(700_000));
        assert!(big.len() < config::MAXIMUM_DOCUMENT_SIZE);
        let mut payloads = [
            text_payload("big.txt", &big),
            text_payload("small.txt", &format!("aws_key = {SECRET}")),
        ];

        let (index, secrets) = scan_for_secrets(&test_config(url), &mut payloads).expect("scan");

        // The oversized document never reached the API.
        assert_eq!(index, 1);
        assert_eq!(secrets.len(), 1);
        let batches = recorded.batches.lock().expect("lock");
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0], ["small.txt"]);
        assert_eq!(recorded.metadata_hits.load(Ordering::SeqCst), 1);
    }

    /// GIVEN a multi-chunk batch where one chunk is refused by the API
    /// WHEN it is scanned
    /// THEN the remaining chunks are still scanned and a secret found in any of
    /// them still blocks — propagating instead threw away what was already found
    /// and failed the whole event open.
    #[test]
    fn a_refused_chunk_does_not_discard_the_other_chunks() {
        for (fail_scan, leaky_at) in [(1, 0), (0, 4)] {
            let (_guard, _dir) = verdict_cache::with_cache_dir();
            let (url, recorded) = mock_api(Mock {
                max_documents_per_scan: 2,
                fail_scan: Some(fail_scan),
                ..Mock::default()
            });
            let mut payloads: Vec<Payload> = (0..6)
                .map(|i| {
                    let content = if i == leaky_at {
                        format!("aws_key = {SECRET}")
                    } else {
                        format!("clean {i}")
                    };
                    text_payload(&format!("file{i}.txt"), &content)
                })
                .collect();

            let (index, secrets) = scan_for_secrets(&test_config(url), &mut payloads)
                .unwrap_or_else(|e| panic!("fail_scan={fail_scan}: {e:?}"));

            assert_eq!(index, leaky_at, "fail_scan={fail_scan}");
            assert_eq!(secrets.len(), 1, "fail_scan={fail_scan}");
            // Every chunk was attempted, the refused one included.
            assert_eq!(recorded.batches.lock().expect("lock").len(), 3);
        }
    }

    /// GIVEN every chunk refused and no secret found anywhere
    /// WHEN the event is scanned
    /// THEN it fails open with the API's reason, rather than reporting "clean".
    #[test]
    fn an_all_refused_scan_fails_open_instead_of_reporting_clean() {
        let (_guard, _dir) = verdict_cache::with_cache_dir();
        let (url, _) = mock_api(Mock {
            max_documents_per_scan: 2,
            // `fail_scan` matches the first request; the mock repeats nothing, so
            // one chunk is enough to prove the error is not swallowed.
            fail_scan: Some(0),
            ..Mock::default()
        });
        let mut payloads = [text_payload("clean.txt", "nothing here")];

        let outcome = scan_for_secrets(&test_config(url), &mut payloads);

        assert!(
            matches!(&outcome, Err(Error::Fail(m)) if m.contains("(refused)")),
            "{:?}",
            outcome.map(|(index, secrets)| (index, secrets.len()))
        );
    }

    /// GIVEN three documents of the maximum size
    /// WHEN they are chunked
    /// THEN the split honours the per-request byte ceiling, not just the count.
    #[test]
    fn chunking_also_splits_on_the_payload_byte_limit() {
        let pending: Vec<Pending> = (0..3)
            .map(|index| Pending {
                index,
                document: api::Document {
                    content: "x".repeat(config::MAXIMUM_DOCUMENT_SIZE),
                    filename: format!("file{index}"),
                },
                key: None,
            })
            .collect();

        let sizes: Vec<usize> = chunks(&pending, 20, config::MAXIMUM_PAYLOAD_SIZE)
            .map(<[Pending]>::len)
            .collect();
        assert_eq!(sizes, [2, 1]);
    }

    /// GIVEN an instance whose token lives in a credential store with no item for
    /// it, so any read surfaces as an auth `Fail`
    /// WHEN an unrecognised agent's payload arrives
    /// THEN it is rejected without the store ever being read — on macOS that read
    /// is what pops the Keychain dialog.
    #[test]
    fn an_unrecognised_agent_is_rejected_without_resolving_the_token() {
        let (_guard, dir) = verdict_cache::with_cache_dir();
        std::fs::write(
            dir.path().join("auth_config.yaml"),
            format!(
                "instances:\n- url: https://keyring-absent.invalid\n  accounts:\n  - token: {}\n",
                config::KEYRING_SENTINEL
            ),
        )
        .expect("write");
        // SAFETY: serialised by the guard above; restored below.
        unsafe {
            std::env::set_var("GG_CONFIG_DIR", dir.path());
            std::env::set_var("GG_USER_HOME_DIR", dir.path());
            std::env::set_var("GITGUARDIAN_INSTANCE", "https://keyring-absent.invalid");
            std::env::set_var("GITGUARDIAN_DONT_LOAD_ENV", "1");
            std::env::remove_var("GITGUARDIAN_API_KEY");
            std::env::remove_var("GGSHIELD_NO_KEYRING");
        }
        let resolved = config::resolve();
        let outcome = resolved.as_ref().map(|config| {
            scan(
                config,
                r#"{"unknown_agent": true, "hook_event_name": "PreToolUse"}"#,
            )
        });
        unsafe {
            std::env::remove_var("GG_CONFIG_DIR");
            std::env::remove_var("GG_USER_HOME_DIR");
            std::env::remove_var("GITGUARDIAN_INSTANCE");
            std::env::remove_var("GITGUARDIAN_DONT_LOAD_ENV");
        }

        assert!(resolved.is_ok(), "config resolution failed: {resolved:?}");
        // An `Error::Fail` here would mean the credential store was read.
        match outcome {
            Ok(Err(Error::Invalid(message))) => assert_eq!(message, "Unrecognized agent"),
            other => panic!("expected an Invalid rejection, got {other:?}"),
        }
    }

    /// GIVEN `exit_zero`
    /// WHEN an exit code is applied
    /// THEN only SCAN_FOUND_PROBLEMS (1) is rewritten to 0.
    #[test]
    fn exit_zero_only_rewrites_the_scan_found_problems_code() {
        assert_eq!(apply_exit_zero(1, true), 0);
        // A config-load failure is not a scan result.
        assert_eq!(apply_exit_zero(128, true), 128);
        assert_eq!(apply_exit_zero(1, false), 1);
        assert_eq!(apply_exit_zero(2, true), 2);
        assert_eq!(apply_exit_zero(0, true), 0);
    }

    /// GIVEN a path
    /// WHEN its extension is tested
    /// THEN only the vendored binary extensions match.
    #[test]
    fn binary_extensions_are_recognised() {
        assert!(is_path_binary(Path::new("/tmp/a.png")));
        assert!(is_path_binary(Path::new("/tmp/a.zip")));
        assert!(!is_path_binary(Path::new("/tmp/a.env")));
        assert!(!is_path_binary(Path::new("/tmp/a")));
    }

    /// GIVEN a Read payload pointing at a path that is not a file
    /// WHEN its scannable content is taken
    /// THEN the payload's own text is scanned instead.
    #[test]
    fn read_payload_for_a_missing_file_falls_back_to_payload_content() {
        let mut p = Payload {
            event_type: EventType::PreToolUse,
            tool: Some(Tool::Read),
            content: "inline".into(),
            identifier: "/nonexistent/nope.txt".into(),
            agent: payload::Agent::Claude,
            raw: serde_json::Value::Object(Default::default()),
            read_range: None,
        };
        assert_eq!(
            scannable(&offline_config(), &mut p),
            Some(("inline".into(), "/nonexistent/nope.txt".into()))
        );
    }

    /// GIVEN a Read payload pointing at a real text file
    /// WHEN its scannable content is taken
    /// THEN the file is read from disk and scanned under its own path.
    #[test]
    fn read_payload_for_an_existing_file_scans_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("creds.env");
        std::fs::write(&path, "TOKEN=abc").expect("write");
        let mut p = Payload {
            event_type: EventType::PreToolUse,
            tool: Some(Tool::Read),
            content: String::new(),
            identifier: path.to_string_lossy().to_string(),
            agent: payload::Agent::Claude,
            raw: serde_json::Value::Object(Default::default()),
            read_range: None,
        };
        let (content, filename) = scannable(&offline_config(), &mut p).expect("scannable");
        assert_eq!(content, "TOKEN=abc");
        assert_eq!(filename, path.to_string_lossy());
    }

    /// GIVEN a file over the API's document ceiling
    /// WHEN the agent reads a range of it
    /// THEN the slice is small enough to scan, where the whole file would have
    /// been skipped.
    #[test]
    fn a_ranged_read_of_an_oversized_file_still_produces_a_scannable_document() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("big.txt");
        let line = "x".repeat(99);
        let content: Vec<String> = (0..20_000).map(|_| line.clone()).collect();
        std::fs::write(&path, content.join("\n")).expect("write");
        assert!(
            std::fs::metadata(&path).expect("stat").len() as usize > config::MAXIMUM_DOCUMENT_SIZE
        );

        let payload = |read_range| Payload {
            event_type: EventType::PreToolUse,
            tool: Some(Tool::Read),
            content: String::new(),
            identifier: path.to_string_lossy().to_string(),
            agent: payload::Agent::Claude,
            raw: serde_json::Value::Object(Default::default()),
            read_range,
        };
        let config = offline_config();
        assert!(
            scannable(&config, &mut payload(None))
                .expect("whole file")
                .0
                .len()
                > config::MAXIMUM_DOCUMENT_SIZE
        );
        let sliced = scannable(&config, &mut payload(Some((1, Some(10)))))
            .expect("slice")
            .0;
        assert!(sliced.len() < config::MAXIMUM_DOCUMENT_SIZE);
        assert_eq!(sliced.lines().count(), 11);
    }

    /// GIVEN the same secret written in each encoding a byte-order mark announces
    /// WHEN the bytes are decoded
    /// THEN the secret comes back verbatim, and no mark is left in the text.
    #[test]
    fn every_byte_order_mark_decodes_to_the_same_text() {
        let text = "AWS_SECRET=byIvSsomethingTXHU\n";

        let utf16 = |big_endian: bool| {
            let mut bytes = if big_endian {
                vec![0xFE, 0xFF]
            } else {
                vec![0xFF, 0xFE]
            };
            for unit in text.encode_utf16() {
                bytes.extend_from_slice(&if big_endian {
                    unit.to_be_bytes()
                } else {
                    unit.to_le_bytes()
                });
            }
            bytes
        };
        let utf32 = |big_endian: bool| {
            let mut bytes = if big_endian {
                vec![0x00, 0x00, 0xFE, 0xFF]
            } else {
                vec![0xFF, 0xFE, 0x00, 0x00]
            };
            for c in text.chars() {
                bytes.extend_from_slice(&if big_endian {
                    (c as u32).to_be_bytes()
                } else {
                    (c as u32).to_le_bytes()
                });
            }
            bytes
        };
        let mut utf8_bom = vec![0xEF, 0xBB, 0xBF];
        utf8_bom.extend_from_slice(text.as_bytes());

        for (name, bytes) in [
            // What PowerShell's `Out-File` writes by default.
            ("utf-16le", utf16(false)),
            ("utf-16be", utf16(true)),
            ("utf-32le", utf32(false)),
            ("utf-32be", utf32(true)),
            ("utf-8 bom", utf8_bom),
            ("utf-8", text.as_bytes().to_vec()),
        ] {
            assert_eq!(decode(&bytes), text, "{name}");
        }
    }

    /// GIVEN bytes that are no valid encoding at all, with an ASCII secret in them
    /// WHEN they are decoded
    /// THEN the secret survives, because skipping the file would allow the read
    /// with nothing scanned.
    #[test]
    fn undecodable_bytes_keep_their_ascii_rather_than_being_skipped() {
        let mut bytes = vec![0x80, 0xFF, 0xFE_u8];
        bytes.extend_from_slice(b"token=byIvSsomethingTXHU");
        bytes.push(0x81);
        assert!(decode(&bytes).contains("token=byIvSsomethingTXHU"));
    }

    /// GIVEN a Read payload pointing at a UTF-16LE file, as PowerShell writes them
    /// WHEN its scannable content is taken
    /// THEN the text is scanned instead of the file being silently skipped.
    #[test]
    fn a_utf16_file_is_scanned_not_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secrets.txt");
        let mut bytes = vec![0xFF, 0xFE];
        for unit in "AWS_SECRET=byIvSsomethingTXHU\n".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        std::fs::write(&path, &bytes).expect("write");
        let mut p = Payload {
            event_type: EventType::PreToolUse,
            tool: Some(Tool::Read),
            content: String::new(),
            identifier: path.to_string_lossy().to_string(),
            agent: payload::Agent::Claude,
            raw: serde_json::Value::Object(Default::default()),
            read_range: None,
        };
        assert_eq!(
            scannable(&offline_config(), &mut p).expect("scannable").0,
            "AWS_SECRET=byIvSsomethingTXHU\n"
        );
    }

    /// GIVEN a whole-file read of a file no encoding could bring under the ceiling
    /// WHEN its scannable content is taken
    /// THEN nothing is read: the bytes would be skipped anyway, and reading them
    /// first is how a multi-GB `@big.log` became an OOM with no verdict at all.
    #[test]
    fn an_oversized_whole_file_read_is_not_read_into_memory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("big.log");
        let file = std::fs::File::create(&path).expect("create");
        // Sparse: 64 MiB of length without 64 MiB on disk or in this process.
        let size = 64 * 1024 * 1024;
        file.set_len(size).expect("set_len");
        drop(file);
        assert!(size > (config::MAXIMUM_DOCUMENT_SIZE * 4) as u64);

        let mut p = Payload {
            event_type: EventType::PreToolUse,
            tool: Some(Tool::Read),
            content: String::new(),
            identifier: path.to_string_lossy().to_string(),
            agent: payload::Agent::Claude,
            raw: serde_json::Value::Object(Default::default()),
            read_range: None,
        };
        assert_eq!(scannable(&offline_config(), &mut p), None);
    }

    /// GIVEN a Read payload pointing at a file with a binary extension
    /// WHEN its scannable content is taken
    /// THEN the file is not read from disk.
    #[test]
    fn binary_files_are_not_read_from_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("image.png");
        std::fs::write(&path, "not really a png").expect("write");
        let mut p = Payload {
            event_type: EventType::PreToolUse,
            tool: Some(Tool::Read),
            content: String::new(),
            identifier: path.to_string_lossy().to_string(),
            agent: payload::Agent::Claude,
            raw: serde_json::Value::Object(Default::default()),
            read_range: None,
        };
        assert_eq!(
            scannable(&offline_config(), &mut p).expect("scannable").0,
            ""
        );
    }

    /// An `ai_discovery.json` in the shape `save_discovery_cache()` writes. Its one
    /// server's Claude Code configuration name mangles to "git_hub", so a resolved
    /// report proves the inventory was read, not echoed.
    const INVENTORY: &str = r#"{
        "user": {"hostname": "laptop", "username": "dev", "machine_id": "m-1",
                 "user_email": "dev@example.com"},
        "discovery_duration": 0.5,
        "servers": [{"name": "GitHub", "tools": [],
                     "configurations": [{"name": "git hub", "agent": "claude-code"}]}]
    }"#;

    fn write_inventory(dir: &Path) {
        std::fs::write(dir.join("ai_discovery.json"), INVENTORY).expect("write inventory");
    }

    /// One Claude Code MCP tool call with nothing incriminating in its arguments.
    fn mcp_event() -> String {
        json!({
            "session_id": "abc",
            "transcript_path": "/Users/x/.claude/projects/p/abc.jsonl",
            "cwd": "/home/dev/proj",
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__git_hub__delete_repository",
            "tool_input": {"owner": "acme", "repo": "prod"},
        })
        .to_string()
    }

    /// GIVEN an MCP tool call whose arguments hold no secret, and an organisation
    /// that does not permit the call
    /// WHEN the event is settled
    /// THEN it blocks with the reason the API gave, and the report it sent names the
    /// canonical server the inventory resolved.
    #[test]
    fn a_call_the_api_does_not_permit_blocks_even_with_clean_arguments() {
        let (_guard, dir) = verdict_cache::with_cache_dir();
        write_inventory(dir.path());
        let (url, recorded) = mock_api(Mock {
            deny: Some("Deleting repositories is not allowed by your organization."),
            ..Mock::default()
        });
        let mut payloads = payload::parse(&mcp_event()).expect("parses");
        let inventory = ggshield_discovery::load_fresh().expect("fresh inventory");

        let (index, verdict) =
            scan_payloads(&test_config(url), &mut payloads, Some(&inventory)).expect("settled");

        assert_eq!(index, 0);
        match verdict {
            Verdict::NotPermitted(reason) => assert_eq!(
                reason,
                "Deleting repositories is not allowed by your organization."
            ),
            other => panic!(
                "expected a denial, got {:?}",
                matches!(other, Verdict::Allowed)
            ),
        }
        let activities = recorded.activities.lock().expect("lock");
        assert_eq!(activities.len(), 1);
        let sent = &activities[0];
        // "mcp__git_hub__delete_repository" split, and "git hub" resolved.
        assert_eq!(sent["server"], "GitHub");
        assert_eq!(sent["tool"], "delete_repository");
        assert_eq!(sent["agent"], "claude-code");
        assert_eq!(sent["cwd"], "/home/dev/proj");
        assert_eq!(sent["model"], "");
        assert_eq!(sent["input"], json!({"owner": "acme", "repo": "prod"}));
        assert_eq!(sent["user"]["machine_id"], "m-1");
        assert_eq!(sent["user"]["user_email"], "dev@example.com");
        // An ISO 8601 instant, which is what marshmallow's DateTime dumps.
        assert!(
            sent["timestamp"]
                .as_str()
                .is_some_and(|t| t.ends_with("+00:00")),
            "{:?}",
            sent["timestamp"]
        );
    }

    /// GIVEN the same call, permitted this time
    /// WHEN the event is settled
    /// THEN it is allowed, and the arguments were still scanned: the two questions
    /// are asked independently.
    #[test]
    fn a_permitted_call_is_allowed_and_its_arguments_are_still_scanned() {
        let (_guard, dir) = verdict_cache::with_cache_dir();
        write_inventory(dir.path());
        let (url, recorded) = mock_api(Mock::default());
        let mut payloads = payload::parse(&mcp_event()).expect("parses");
        let inventory = ggshield_discovery::load_fresh().expect("fresh inventory");

        let (_, verdict) =
            scan_payloads(&test_config(url), &mut payloads, Some(&inventory)).expect("settled");

        assert!(matches!(verdict, Verdict::Allowed));
        assert_eq!(recorded.activities.lock().expect("lock").len(), 1);
        assert_eq!(recorded.batches.lock().expect("lock").len(), 1);
    }

    /// GIVEN an MCP tool call and no inventory to check it against — no cache file,
    /// then one older than the TTL
    /// WHEN the event is scanned
    /// THEN it is declined, which the dispatcher turns into `Outcome::Delegate` and
    /// answers from `ggshield-py`. Never an allow: failing open here would make
    /// deleting a cache file enough to lift an administrator's block.
    #[test]
    fn a_stale_inventory_hands_the_event_over_instead_of_allowing_it() {
        let (_guard, dir) = verdict_cache::with_cache_dir();
        let (url, recorded) = mock_api(Mock::default());
        let config = test_config(url);

        // No inventory at all.
        assert!(
            matches!(scan(&config, &mcp_event()), Err(Error::Unsupported(_))),
            "an absent inventory must decline, not allow"
        );

        // One from two hours ago: written, but past the TTL the Python honours.
        write_inventory(dir.path());
        let stale = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        std::fs::File::options()
            .write(true)
            .open(dir.path().join("ai_discovery.json"))
            .expect("open")
            .set_modified(stale)
            .expect("set mtime");
        assert!(
            matches!(scan(&config, &mcp_event()), Err(Error::Unsupported(_))),
            "a stale inventory must decline, not allow"
        );
        // Declining costs no requests: the answer is Python's, whole.
        assert_eq!(recorded.activities.lock().expect("lock").len(), 0);
        assert_eq!(recorded.batches.lock().expect("lock").len(), 0);
        // ...and the debounce is untouched, so `ggshield-py` does not answer the
        // hand-over with silence because it thinks it has seen this payload.
        assert!(!dir.path().join("latest_ai_hook.txt").exists());

        // Refreshed: handled natively, no hand-over.
        write_inventory(dir.path());
        assert!(scan(&config, &mcp_event()).is_ok());
        assert_eq!(recorded.activities.lock().expect("lock").len(), 1);
    }

    /// GIVEN an MCP tool call that takes no arguments — nothing to scan, so the
    /// token is needed for the policy check and nothing else — and a credential
    /// store that cannot answer
    /// WHEN the event is scanned
    /// THEN it fails open with a warning, as Python does by needing the token before
    /// it can ask at all. A silent allow here would wave through every
    /// argument-less MCP tool without one request or one word to the user.
    #[test]
    fn an_unreadable_token_warns_instead_of_allowing_an_argument_less_call() {
        let (_guard, dir) = verdict_cache::with_cache_dir();
        write_inventory(dir.path());
        std::fs::write(
            dir.path().join("auth_config.yaml"),
            format!(
                "instances:\n- url: https://keyring-absent.invalid\n  accounts:\n  - token: {}\n",
                config::KEYRING_SENTINEL
            ),
        )
        .expect("write");
        // SAFETY: serialised by the guard above; restored below.
        unsafe {
            std::env::set_var("GG_CONFIG_DIR", dir.path());
            std::env::set_var("GG_USER_HOME_DIR", dir.path());
            std::env::set_var("GITGUARDIAN_INSTANCE", "https://keyring-absent.invalid");
            std::env::set_var("GITGUARDIAN_DONT_LOAD_ENV", "1");
            std::env::remove_var("GITGUARDIAN_API_KEY");
            std::env::remove_var("GGSHIELD_NO_KEYRING");
        }
        let resolved = config::resolve();
        let outcome = resolved.as_ref().map(|config| {
            scan(
                config,
                &json!({
                    "session_id": "abc",
                    "transcript_path": "/Users/x/.claude/projects/p/abc.jsonl",
                    "hook_event_name": "PreToolUse",
                    "tool_name": "mcp__git_hub__list_repositories",
                })
                .to_string(),
            )
        });
        unsafe {
            std::env::remove_var("GG_CONFIG_DIR");
            std::env::remove_var("GG_USER_HOME_DIR");
            std::env::remove_var("GITGUARDIAN_INSTANCE");
            std::env::remove_var("GITGUARDIAN_DONT_LOAD_ENV");
        }

        assert!(resolved.is_ok(), "config resolution failed: {resolved:?}");
        match outcome {
            Ok(Err(Error::Fail(warning))) => {
                assert!(warning.contains("could not authenticate"), "{warning}")
            }
            other => panic!("expected a fail-open warning, got {other:?}"),
        }
    }

    /// GIVEN an event where a secret and a denial land on different payloads, and
    /// then on the same one
    /// WHEN the verdicts are applied
    /// THEN the earlier payload's verdict wins, and on a tie the scan does —
    /// `_scan_payloads()`'s order, which decides which message the user sees.
    #[test]
    fn the_earlier_payload_wins_and_a_tie_goes_to_the_scan() {
        let secrets = || Some((1, Vec::new()));
        let denial = |index| Some((index, "denied".to_string()));

        assert!(matches!(apply(secrets(), denial(2)).1, Verdict::Secrets(_)));
        assert!(matches!(
            apply(secrets(), denial(0)).1,
            Verdict::NotPermitted(_)
        ));
        // Same payload: Python's loop checks the scan result first.
        assert!(matches!(apply(secrets(), denial(1)).1, Verdict::Secrets(_)));
        assert_eq!(apply(secrets(), denial(0)).0, 0);
        assert!(matches!(apply(None, None).1, Verdict::Allowed));
    }

    /// GIVEN an MCP payload at PostToolUse, and a non-MCP tool call at PreToolUse
    /// WHEN the event is settled with a denying API
    /// THEN neither reports activity: `is_mcp_activity_payload()` is a PreToolUse on
    /// an MCP tool and nothing else, and there is nothing to permit after the fact.
    #[test]
    fn only_a_pre_tool_use_on_an_mcp_tool_is_activity() {
        let (_guard, dir) = verdict_cache::with_cache_dir();
        write_inventory(dir.path());
        let (url, recorded) = mock_api(Mock {
            deny: Some("nope"),
            ..Mock::default()
        });
        let config = test_config(url);
        for event in [
            json!({"session_id": "a", "transcript_path": "/x/.claude/p.jsonl",
                   "hook_event_name": "PostToolUse",
                   "tool_name": "mcp__git_hub__delete_repository",
                   "tool_input": {"repo": "prod"},
                   "tool_response": {"ok": true}}),
            json!({"session_id": "a", "transcript_path": "/x/.claude/p.jsonl",
                   "hook_event_name": "PreToolUse", "tool_name": "WebFetch",
                   "tool_input": {"url": "https://example.com"}}),
        ] {
            let code = scan(&config, &event.to_string()).expect("settled");
            assert_eq!(code, 0, "{event}");
        }
        assert_eq!(recorded.activities.lock().expect("lock").len(), 0);
    }
}
