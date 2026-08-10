//! `ggshield secret scan ai-hook`, natively.
//!
//! Same job as the Python command: read a hook event on stdin, decide what to
//! scan, ask GitGuardian, print the agent's verdict JSON, exit 0. Detection is
//! server-side, so this is transport and glue — no rules live here.
//!
//! The reason it exists is startup: the Python hook fires twice per tool call
//! and pays ~440 ms of frozen-interpreter boot plus ~135 ms of config/keychain
//! work each time, before the ~380 ms API round trip that is actually doing the
//! work. A compiled binary deletes the first two.
//!
//! Every verdict here has to mean the same thing as the Python one, so anything
//! this binary cannot reproduce declines and fails open with a warning instead of
//! guessing — see `config::dotenv_overrides()` and `user_config`.

mod api;
mod message;
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

fn main() {
    let mut buffer = Vec::new();
    let _ = std::io::stdin()
        .lock()
        .take(MAX_READ_SIZE)
        .read_to_end(&mut buffer);
    let stdin_content = String::from_utf8_lossy(&buffer).trim().to_string();

    // A panic must not reach the agent as a crash: an agent reads a non-zero
    // exit with no JSON as "the hook is broken", and the user is never told
    // scanning silently stopped. Treat it as any other internal failure.
    let outcome = std::panic::catch_unwind(|| run(&stdin_content))
        .unwrap_or_else(|_| Err(Error::scan("internal error")));

    let code = match outcome {
        Ok(code) => code,
        Err(err) => handle_error(&stdin_content, err),
    };
    std::process::exit(code);
}

/// The three failure modes of `ai_hook_cmd`, which behave very differently.
fn handle_error(stdin_content: &str, err: Error) -> i32 {
    let warning = match err {
        // `except ValueError`: stderr, exit 1, nothing on stdout.
        Error::Invalid(message) => {
            eprintln!("{message}");
            return 1;
        }
        // Raised while loading config, before the command's try block exists.
        // ExitCode.UNEXPECTED_ERROR, and no fail-open.
        Error::Fatal(message) => {
            eprintln!("Error: {message}");
            return 128;
        }
        Error::Fail(warning) => warning,
    };

    // `emit_fail_open_response()`: warn, then allow *with* the warning attached
    // so the user learns the action went unscanned.
    eprintln!("Warning: {warning}");
    match payload::parse(stdin_content) {
        // We cannot even tell who is calling, so no well-formed response is
        // possible. Agents treat exit 1 as a non-blocking error.
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
    // even for a duplicate payload. The OS credential-store read is the one part
    // left for later — see `Config::token`.
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
    // agent's context, so tell the user out-of-band. Best effort, never allowed
    // to break the verdict.
    if payload.event_type == EventType::PostToolUse {
        notify(&result);
    }
    Ok(output::output_result(&result))
}

/// One payload still waiting for an API answer, and the cache key that answer
/// would be stored under.
///
/// `index` is the payload the document came from. It has to travel with the
/// document, because the batch is not the payload list — empty, over-size and
/// already-cached payloads are left out of it — so a position in the batch says
/// nothing about a position in the event.
struct Pending {
    index: usize,
    document: api::Document,
    /// The verdict-cache key, or `None` for a document that is not cacheable —
    /// one past the 1 MiB threshold, matching hooks.py, which keys the cache on
    /// empty content for those.
    key: Option<String>,
}

/// `_scan_payloads()` plus `_scan_contents()`: scan everything the event still
/// needs scanned, in as few requests as possible.
///
/// Returns the secrets found and the index of the first payload holding them, or
/// index 0 with no secrets — the caller only reads that payload for its output
/// contract. One event routinely carries several payloads (a prompt mentioning N
/// files produces N+1, a `cat` command 2) and each request costs a round trip.
///
/// `send_mcp_activity()`, which Python also calls per payload to ask the API
/// whether an MCP tool call is allowed by policy, is not implemented. No warning
/// either: it swallows every exception and returns "allowed" (mcp.py), so warning
/// would be louder than Python is on its own failure path.
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
        let Some((content, filename)) = scannable(payload) else {
            continue;
        };
        // Empty content is no API call at all.
        if content.is_empty() {
            continue;
        }
        // A document over the instance's ceiling is skipped, exactly as
        // `_start_scans()` does (`scanner_ui.on_skipped`); sending it anyway
        // would earn a 400 and fail the whole event open. A skip is not a block.
        if content.len() > api::max_document_size(config) {
            continue;
        }

        // hooks.py keys the verdict cache on empty content past
        // `DOCUMENT_SIZE_THRESHOLD_BYTES`, i.e. a document over 1 MiB is scanned
        // but never cached. The instance ceiling above must not change what is
        // cacheable, so the gate stays the compiled-in threshold.
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
        // it debounces on raw stdin, and those two payloads differ.
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
    let max_documents = api::max_documents_per_scan(config);
    let max_payload_size = api::max_payload_size(config);
    for chunk in chunks(&pending, max_documents, max_payload_size) {
        let results = api::multiscan(config, agent, chunk.iter().map(|item| &item.document))?;
        // /v1/multiscan answers one result per document, in the order they were
        // sent. Any other count is a degraded answer that cannot be attributed:
        // zip stops at the shorter side rather than shifting secrets onto their
        // neighbours.
        let unambiguous = results.len() == chunk.len();
        for (item, result) in chunk.iter().zip(results) {
            // `filtered_out` must be 0 as well: an empty `secrets` can also mean
            // the API reported breaks that this project's ignore rules dropped,
            // and caching that would let one project's rule allow the same content
            // in a project without it.
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
    Ok(found.unwrap_or((0, Vec::new())))
}

/// `_start_scans()`'s chunking: the API caps a scan both in documents and in
/// bytes. Going over either is a 400 — a failed scan, which here means failing
/// open — so the batch is split rather than sent whole.
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
            // A document that fits in no batch at all would otherwise loop
            // forever; send it alone and let the API judge it.
            .max(1);
        let (chunk, tail) = rest.split_at(take);
        rest = tail;
        Some(chunk)
    })
}

/// For a Read tool pointing at a real, non-binary file the *file* is scanned,
/// not the payload text. Everything else scans the payload content under the
/// identifier as its filename.
///
/// The content is moved out of the payload rather than copied: a document can be
/// a whole MiB, and nothing downstream reads it again.
fn scannable(payload: &mut Payload) -> Option<(String, String)> {
    if payload.tool == Some(Tool::Read) {
        let path = Path::new(&payload.identifier);
        if path.is_file() && !is_path_binary(path) {
            // Python skips a file it cannot decode ("can't detect encoding")
            // rather than scanning mojibake; a skip is not a block.
            let content = std::fs::read(path).ok()?;
            let content = String::from_utf8(content).ok()?;
            // Only the lines the agent asked for reach the model. Sending the
            // whole file instead can push it over the document ceiling, and a
            // skipped document is an allowed read.
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

/// `is_path_binary()`: extension test only, same list as ggshield.
fn is_path_binary(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| binary_extensions::BINARY_EXTENSIONS.contains(&ext))
}

/// `has_already_been_seen()`. Some setups install hooks from several assistants
/// and invoke us twice with an identical payload.
///
/// No file lock, unlike the Python (which uses `filelock`): losing the race means
/// two processes both scan the same payload — slower, never less safe.
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
/// The message embeds attacker-influenced command text, so the strings are passed
/// as arguments to the AppleScript run handler rather than interpolated into its
/// source.
#[cfg(target_os = "macos")]
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
    let _ = std::process::Command::new("osascript")
        .args([
            "-e",
            "on run argv",
            "-e",
            "display notification (item 1 of argv) with title (item 2 of argv)",
            "-e",
            "end run",
            "--",
            &body,
            "ggshield - Secrets Detected",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

#[cfg(not(target_os = "macos"))]
fn notify(_result: &HookResult) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// Recognised by the mock below as "this document holds a secret".
    const SECRET: &str = "AKIAsomething";

    /// What the mock reports on `/v1/metadata`.
    #[derive(Clone, Copy)]
    struct MockLimits {
        max_documents_per_scan: usize,
        max_document_size: usize,
    }

    impl Default for MockLimits {
        fn default() -> Self {
            MockLimits {
                max_documents_per_scan: config::DEFAULT_MAX_DOCUMENTS_PER_SCAN,
                max_document_size: config::MAXIMUM_DOCUMENT_SIZE,
            }
        }
    }

    /// What the mock recorded: every multiscan batch's filenames, plus how many
    /// times `/v1/metadata` was fetched (never more than once per run).
    struct Recorded {
        batches: Mutex<Vec<Vec<String>>>,
        metadata_hits: AtomicUsize,
    }

    /// A localhost stand-in for the API: answers `/v1/metadata` (with the given
    /// limits) and `/v1/multiscan`, recording what it was sent. Nothing ever
    /// leaves the machine.
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
    /// answering — as the real one does — exactly one result per document, in the
    /// order the documents were sent.
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
            } = limits;
            format!(
                r#"{{"preferences": {{"general__maximum_payload_size": 2621440}}, "secret_scan_preferences": {{"maximum_document_size": {max_document_size}, "maximum_documents_per_scan": {max_documents_per_scan}}}}}"#
            )
        } else {
            let mut raw = vec![0u8; length];
            reader.read_exact(&mut raw).expect("body");
            let documents: Vec<serde_json::Value> =
                serde_json::from_slice(&raw).expect("documents");
            recorded.batches.lock().expect("lock").push(
                documents
                    .iter()
                    .map(|d| d["filename"].as_str().unwrap_or_default().to_string())
                    .collect(),
            );
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
    /// payload holding it rather than to its position in the batch — the empty
    /// payload never reaches the API, so the two do not line up.
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
        // The limits are resolved once, not once per document.
        assert_eq!(recorded.metadata_hits.load(Ordering::SeqCst), 1);
    }

    /// GIVEN an instance reporting a raised `maximum_documents_per_scan`
    /// WHEN a larger batch is scanned
    /// THEN it is chunked to what the instance reports, not to the default: one
    /// document past the instance limit the API answers 400 and the scan fails
    /// open.
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
    /// THEN it is still chunked to the instance limit. Assuming the default here
    /// is the fail-open this closes: the oversized batch earns a 400 and the whole
    /// event goes unscanned.
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
    /// THEN it reaches the API and blocks, instead of being skipped — a skipped
    /// document is an allowed action.
    #[test]
    fn a_large_document_under_the_raised_instance_limit_is_scanned() {
        let (_guard, _dir) = verdict_cache::with_cache_dir();
        let (url, recorded) = mock_api(MockLimits {
            max_document_size: 4 * 1024 * 1024,
            ..MockLimits::default()
        });
        // ~2 MiB: over the 1 MiB trigger, under the 4 MiB instance limit, with a
        // secret buried inside.
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
    /// THEN it is skipped rather than sent. Sending it earns a 400, and a failed
    /// scan here fails the whole event open unscanned.
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

        // The oversized document never reached the API, and the rest of the event
        // was still scanned.
        assert_eq!(index, 1);
        assert_eq!(secrets.len(), 1);
        let batches = recorded.batches.lock().expect("lock");
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0], ["small.txt"]);
        assert_eq!(recorded.metadata_hits.load(Ordering::SeqCst), 1);
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

        // Two documents of the maximum size fit in one request body, three do not.
        let sizes: Vec<usize> = chunks(&pending, 20, config::MAXIMUM_PAYLOAD_SIZE)
            .map(<[Pending]>::len)
            .collect();
        assert_eq!(sizes, [2, 1]);
    }

    /// GIVEN an instance whose token lives in a credential store that has no item
    /// for it, so any attempt to read it surfaces as an auth `Fail`
    /// WHEN an unrecognised agent's payload arrives
    /// THEN it is rejected as unparseable without the store ever being read. On
    /// macOS that read is what pops the Keychain dialog, twice per tool call.
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
            // Neither the developer's own config nor their real instance.
            std::env::set_var("GG_USER_HOME_DIR", dir.path());
            std::env::set_var("GITGUARDIAN_INSTANCE", "https://keyring-absent.invalid");
            std::env::set_var("GITGUARDIAN_DONT_LOAD_ENV", "1");
            // An exported key would bypass the credential store entirely.
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
        // 128 is a config-load failure, not a scan result.
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
            scannable(&mut p),
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
        let (content, filename) = scannable(&mut p).expect("scannable");
        assert_eq!(content, "TOKEN=abc");
        assert_eq!(filename, path.to_string_lossy());
    }

    /// GIVEN a file over the API's document ceiling
    /// WHEN the agent reads a range of it
    /// THEN the slice is small enough to scan, where the whole file would have
    /// been skipped and the read allowed.
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
        assert!(
            scannable(&mut payload(None)).expect("whole file").0.len()
                > config::MAXIMUM_DOCUMENT_SIZE
        );
        let sliced = scannable(&mut payload(Some((1, Some(10)))))
            .expect("slice")
            .0;
        assert!(sliced.len() < config::MAXIMUM_DOCUMENT_SIZE);
        // 10 requested lines plus the one line of slack on the far side.
        assert_eq!(sliced.lines().count(), 11);
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
        assert_eq!(scannable(&mut p).expect("scannable").0, "");
    }
}
