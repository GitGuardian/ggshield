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
    if !stdin_content.is_empty() && has_already_been_seen(stdin_content) {
        return Ok(0);
    }

    let mut payloads = payload::parse(stdin_content)?;
    let (index, secrets) = scan_payloads(config, &mut payloads)?;
    let payload = &payloads[index];

    if secrets.is_empty() {
        return Ok(output::output_result(&HookResult::allow(payload)));
    }

    let result = HookResult::block(
        payload,
        message::from_secrets(&secrets, payload),
        secrets.len(),
    );
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

/// `_scan_payloads()` plus `_scan_contents()`: scan everything the event still
/// needs scanned, in as few requests as possible.
///
/// Returns the secrets found and the index of the first payload holding them, or
/// index 0 with no secrets — the caller only reads that payload for its output
/// contract.
///
/// `send_mcp_activity()` is not implemented, and not warned about either: it
/// swallows every exception and returns "allowed" (mcp.py).
fn scan_payloads(
    config: &config::Config,
    payloads: &mut [Payload],
) -> Result<(usize, Vec<api::Secret>), Error> {
    if payloads.is_empty() {
        return Err(Error::Invalid("Error: no payloads to scan".into()));
    }
    let agent = payloads[0].agent;

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
        return Ok((0, Vec::new()));
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
    match (found, failure) {
        // A secret beats a partial failure: blocking on what was found is never
        // worse than failing the whole event open.
        (Some(found), _) => Ok(found),
        (None, Some(failure)) => Err(failure),
        (None, None) => Ok((0, Vec::new())),
    }
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
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Recognised by the mock below as "this document holds a secret".
    const SECRET: &str = "AKIAsomething";

    /// What the mock reports on `/v1/metadata`, plus which multiscan it refuses.
    #[derive(Clone, Copy)]
    struct MockLimits {
        max_documents_per_scan: usize,
        max_document_size: usize,
        /// The 0-based multiscan request that answers 400 instead of a verdict.
        fail_scan: Option<usize>,
    }

    impl Default for MockLimits {
        fn default() -> Self {
            MockLimits {
                max_documents_per_scan: config::DEFAULT_MAX_DOCUMENTS_PER_SCAN,
                max_document_size: config::MAXIMUM_DOCUMENT_SIZE,
                fail_scan: None,
            }
        }
    }

    /// Every multiscan batch's filenames, plus the `/v1/metadata` fetch count.
    struct Recorded {
        batches: Mutex<Vec<Vec<String>>>,
        metadata_hits: AtomicUsize,
    }

    /// A localhost stand-in for the API: answers `/v1/metadata` (with the given
    /// limits) and `/v1/multiscan`, recording what it was sent.
    fn mock_api(limits: MockLimits) -> (String, Arc<Recorded>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let recorded = Arc::new(Recorded {
            batches: Mutex::new(Vec::new()),
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

    /// One request: the metadata a client reads before chunking, or a multiscan
    /// answering one result per document, in the order they were sent.
    fn serve(mut stream: TcpStream, recorded: &Recorded, limits: MockLimits) {
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
            let MockLimits {
                max_documents_per_scan,
                max_document_size,
                ..
            } = limits;
            format!(
                r#"{{"preferences": {{"general__maximum_payload_size": 2621440}}, "secret_scan_preferences": {{"maximum_document_size": {max_document_size}, "maximum_documents_per_scan": {max_documents_per_scan}}}}}"#
            )
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
        let (url, recorded) = mock_api(MockLimits::default());
        let mut payloads = [
            text_payload("empty.txt", ""),
            text_payload("clean.txt", "nothing here"),
            text_payload("leaky.txt", &format!("aws_key = {SECRET}")),
            text_payload("also-clean.txt", "nothing here either"),
        ];

        let (index, secrets) = scan_payloads(&test_config(url), &mut payloads).expect("scan");

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
        let (url, recorded) = mock_api(MockLimits {
            max_documents_per_scan: 8,
            ..MockLimits::default()
        });
        let mut payloads: Vec<Payload> = (0..21)
            .map(|i| text_payload(&format!("file{i}.txt"), &format!("content {i}")))
            .collect();

        let (_, secrets) = scan_payloads(&test_config(url), &mut payloads).expect("scan");

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
        let (url, recorded) = mock_api(MockLimits {
            max_documents_per_scan: 3,
            ..MockLimits::default()
        });
        let mut payloads: Vec<Payload> = (0..8)
            .map(|i| text_payload(&format!("file{i}.txt"), &format!("content {i}")))
            .collect();

        let (_, secrets) = scan_payloads(&test_config(url), &mut payloads).expect("scan");

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
        let (url, recorded) = mock_api(MockLimits {
            max_document_size: 4 * 1024 * 1024,
            ..MockLimits::default()
        });
        // Over the 1 MiB trigger, under the 4 MiB instance limit.
        let big = format!(
            "{}\n{SECRET}\n{}",
            "x".repeat(1_500_000),
            "y".repeat(600_000)
        );
        assert!(big.len() > config::MAXIMUM_DOCUMENT_SIZE);
        let mut payloads = [text_payload("big.txt", &big)];

        let (index, secrets) = scan_payloads(&test_config(url), &mut payloads).expect("scan");

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
        let (url, recorded) = mock_api(MockLimits {
            max_document_size: 512 * 1024,
            ..MockLimits::default()
        });
        let big = format!("{SECRET}\n{}", "x".repeat(700_000));
        assert!(big.len() < config::MAXIMUM_DOCUMENT_SIZE);
        let mut payloads = [
            text_payload("big.txt", &big),
            text_payload("small.txt", &format!("aws_key = {SECRET}")),
        ];

        let (index, secrets) = scan_payloads(&test_config(url), &mut payloads).expect("scan");

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
            let (url, recorded) = mock_api(MockLimits {
                max_documents_per_scan: 2,
                fail_scan: Some(fail_scan),
                ..MockLimits::default()
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

            let (index, secrets) = scan_payloads(&test_config(url), &mut payloads)
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
        let (url, _) = mock_api(MockLimits {
            max_documents_per_scan: 2,
            // `fail_scan` matches the first request; the mock repeats nothing, so
            // one chunk is enough to prove the error is not swallowed.
            fail_scan: Some(0),
            ..MockLimits::default()
        });
        let mut payloads = [text_payload("clean.txt", "nothing here")];

        let outcome = scan_payloads(&test_config(url), &mut payloads);

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
}
