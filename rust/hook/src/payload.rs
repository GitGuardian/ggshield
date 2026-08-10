//! Hook payload parsing and agent detection. Mirrors `parse_hook_input()`
//! and `_detect_agent()` in `ggshield/verticals/ai/hooks.py`.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use ggshield_common::error::Error;

pub use ggshield_common::hash::sha256_hex;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EventType {
    UserPrompt,
    PreToolUse,
    PostToolUse,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tool {
    Bash,
    Read,
    Mcp,
    Other,
}

/// The five assistants ggshield supports, in the registry order of `AGENTS`
/// (agents/__init__.py). Detection takes the FIRST match, so the order is part of
/// the contract.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Agent {
    Claude,
    Codex,
    Copilot,
    Cursor,
    VsCode,
}

pub const AGENTS: [Agent; 5] = [
    Agent::Claude,
    Agent::Codex,
    Agent::Copilot,
    Agent::Cursor,
    Agent::VsCode,
];

impl Agent {
    /// Sent as the `GGShield-Agent-Name` header.
    pub fn name(self) -> &'static str {
        match self {
            Agent::Claude => "claude-code",
            Agent::Codex => "codex",
            Agent::Copilot => "copilot",
            Agent::Cursor => "cursor",
            Agent::VsCode => "vscode",
        }
    }

    /// Used in the desktop notification text.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn display_name(self) -> &'static str {
        match self {
            Agent::Claude => "Claude Code",
            Agent::Codex => "Codex",
            Agent::Copilot => "Copilot CLI",
            Agent::Cursor => "Cursor",
            Agent::VsCode => "VSCode",
        }
    }

    /// `is_caller()`. The shapes overlap enough that a near-miss misroutes a
    /// payload, and a misrouted payload means emitting a verdict in a schema the
    /// caller ignores.
    fn is_caller(self, data: &Value) -> bool {
        // `hook_payload.get("transcript_path") or ""`: a null and a missing key
        // both read as the empty string.
        let transcript = data
            .get("transcript_path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match self {
            Agent::Claude => data.get("session_id").is_some() && transcript.contains("claude"),
            Agent::Codex => {
                data.get("turn_id").is_some() || transcript.to_lowercase().contains(".codex")
            }
            // Copilot CLI emits only the default fields, which is itself the
            // signature: an exact key-set match once the optional fields are
            // removed.
            Agent::Copilot => {
                const DEFAULT_FIELDS: [&str; 4] =
                    ["hook_event_name", "session_id", "timestamp", "cwd"];
                const OPTIONAL_FIELDS: [&str; 4] =
                    ["prompt", "tool_name", "tool_input", "tool_result"];
                let Some(map) = data.as_object() else {
                    return false;
                };
                let remaining: Vec<&str> = map
                    .keys()
                    .map(String::as_str)
                    .filter(|k| !OPTIONAL_FIELDS.contains(k))
                    .collect();
                remaining.len() == DEFAULT_FIELDS.len()
                    && DEFAULT_FIELDS.iter().all(|f| remaining.contains(f))
            }
            Agent::Cursor => data.get("cursor_version").is_some(),
            Agent::VsCode => transcript.to_lowercase().contains("github.copilot-chat"),
        }
    }

    /// `_detect_agent()`. First match in registry order wins.
    pub fn detect(data: &Value) -> Option<Agent> {
        AGENTS.into_iter().find(|agent| agent.is_caller(data))
    }

    /// `Agent.event_cwd()`: the working directory the event happened in. Used
    /// to resolve a relative Read path to the same absolute identifier a tool
    /// call would produce, so both share one verdict-cache key. "" when unknown.
    fn event_cwd(self, data: &Value) -> String {
        match self {
            // Cursor reports its workspace roots instead of a `cwd`; the first
            // root is the event's working directory.
            Agent::Cursor => data
                .get("workspace_roots")
                .and_then(Value::as_array)
                .and_then(|roots| roots.first())
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            _ => lookup_str(data, &["cwd"]),
        }
    }

    /// `Agent.read_range()`: the lines a read tool call is about to expose.
    /// `None` means the whole file, which is what an absent or unusable parameter
    /// must resolve to — reading too little lets content reach the model unscanned.
    fn read_range(self, tool_input: &Value) -> Option<ReadRange> {
        // `isinstance(x, int) and x > 0`. A float or a string reads as absent.
        let positive = |key: &str| {
            tool_input
                .get(key)
                .and_then(Value::as_u64)
                .filter(|n| *n > 0)
        };
        match self {
            // `offset` (first line) and `limit` (number of lines), either of
            // which can be absent. Read caps an open-ended read at a default
            // number of lines, but the payload does not say what that cap is.
            Agent::Claude => {
                let first = positive("offset").unwrap_or(1);
                match positive("limit") {
                    Some(limit) => Some((first, Some(first + limit - 1))),
                    None if first == 1 => None,
                    None => Some((first, None)),
                }
            }
            // VS Code's read_file takes `startLine`/`endLine`, 1-based and
            // inclusive.
            Agent::VsCode => {
                let first = positive("startLine").unwrap_or(1);
                let last = positive("endLine");
                if first == 1 && last.is_none() {
                    None
                } else {
                    Some((first, last))
                }
            }
            // No range ever seen from these three: Copilot CLI's `view` carries
            // only `path`, Cursor's Read mimics Claude's without the range keys,
            // and Codex shells out to `cat`/`Get-Content`.
            Agent::Codex | Agent::Copilot | Agent::Cursor => None,
        }
    }
}

/// A range of lines an agent is about to read: `(first, last)`, 1-based and
/// inclusive, `last` being `None` for "up to the end of the file".
pub type ReadRange = (u64, Option<u64>);

/// `line_slice()`: lines `first` to `last` of `content`, 1-based and inclusive.
///
/// Split on "\n" only, the way agents number lines: `str::lines()` (and Python's
/// `splitlines()`) also break on vertical tab and friends, which would shift every
/// line number after the first such character. A CRLF file keeps its "\r" — what
/// we scan is a verbatim extract of what the agent reads.
///
/// One line of slack on each side, because agents document their ranges in their
/// own conventions: an extra line costs nothing, a missing one lets content reach
/// the model unscanned.
pub fn line_slice(content: &str, (first, last): ReadRange) -> String {
    let lines: Vec<&str> = content.split('\n').collect();
    // Python's `lines[max(0, first - 2) : None if last is None else last + 1]`,
    // with the same clamping a Python slice does at both ends.
    let start = first.saturating_sub(2).min(lines.len() as u64) as usize;
    let end = last
        .map_or(lines.len() as u64, |last| last.saturating_add(1))
        .min(lines.len() as u64) as usize;
    if start >= end {
        return String::new();
    }
    lines[start..end].join("\n")
}

#[derive(Debug, Clone)]
pub struct Payload {
    pub event_type: EventType,
    pub tool: Option<Tool>,
    pub content: String,
    pub identifier: String,
    pub agent: Agent,
    /// The original hook JSON. Empty object for the synthesised payloads, as in
    /// Python (`raw={}`). Only read for the desktop notification's command text.
    pub raw: Value,
    /// The lines a `Tool::Read` is about to expose, see `Agent::read_range()`.
    /// `None` means the whole file.
    pub read_range: Option<ReadRange>,
}

fn lookup<'a>(data: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| data.get(*key))
}

fn lookup_str(data: &Value, keys: &[&str]) -> String {
    lookup(data, keys)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn event_type_from_name(name: &str) -> EventType {
    match name.to_lowercase().as_str() {
        // "userpromptsubmitted" is Copilot CLI's spelling, "beforesubmitprompt"
        // Cursor's.
        "userpromptsubmit" | "userpromptsubmitted" | "beforesubmitprompt" => EventType::UserPrompt,
        "pretooluse" => EventType::PreToolUse,
        "posttooluse" => EventType::PostToolUse,
        _ => EventType::Other,
    }
}

fn parse_tool(data: &Value) -> Tool {
    let name = lookup_str(data, &["tool_name"]).to_lowercase();
    if name.starts_with("mcp") {
        return Tool::Mcp;
    }
    match name.as_str() {
        "shell" | "bash" | "run_in_terminal" => Tool::Bash,
        "read" | "read_file" | "view" => Tool::Read,
        _ => Tool::Other,
    }
}

/// Python truthiness, for the `elif tool_input:` branch.
fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn file_path_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Character-for-character _FILE_PATH_REGEX from hooks.py, with Python's
        // re.MULTILINE expressed as the inline (?m) flag.
        Regex::new(concat!(
            r#"(?m)@"((?:[^"\\]|\\.)*)""#,
            r"|",
            r"(?:\W|^)@",
            r"(?:file:)?",
            r"([\w/\\.-]+)",
        ))
        .expect("static regex")
    })
}

/// `find_filepaths()`. Sorted rather than a `set` with Python's arbitrary
/// iteration order, so which payload blocks first is deterministic.
pub fn find_filepaths(prompt: &str) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for caps in file_path_regex().captures_iter(prompt) {
        let raw = caps
            .get(1)
            .or_else(|| caps.get(2))
            .map(|m| m.as_str())
            .unwrap_or_default();
        let path = raw.trim().strip_suffix('.').unwrap_or(raw.trim());
        if !path.is_empty() {
            paths.insert(path.to_string());
        }
    }
    paths
}

/// `_abs_read_path()`: resolve a Read identifier against the event's `cwd`, so a
/// relative @-mention and an absolute tool `file_path` for one file share a single
/// verdict-cache key.
///
/// Lexical and POSIX only, matching `os.path.abspath(os.path.join(cwd,
/// identifier))`: no filesystem access, no symlink resolution, no drive letters.
fn abs_read_path(identifier: &str, cwd: &str) -> String {
    if identifier.is_empty() || cwd.is_empty() {
        return identifier.to_string();
    }
    let joined = if identifier.starts_with('/') {
        identifier.to_string()
    } else {
        format!("{cwd}/{identifier}")
    };
    normpath(&joined)
}

/// Lexical `os.path.normpath` for POSIX: squeeze repeated `/`, drop `.`, resolve
/// `..`. No filesystem access.
fn normpath(path: &str) -> String {
    let is_absolute = path.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => match out.last() {
                Some(&last) if last != ".." => {
                    out.pop();
                }
                // A leading `..` is kept on a relative path but dropped past the
                // root of an absolute one, as normpath does.
                _ if !is_absolute => out.push(".."),
                _ => {}
            },
            _ => out.push(part),
        }
    }
    let joined = out.join("/");
    if is_absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".to_string()
    } else {
        joined
    }
}

fn read_payload(identifier: String, agent: Agent) -> Payload {
    Payload {
        event_type: EventType::UserPrompt,
        tool: Some(Tool::Read),
        content: String::new(),
        identifier,
        agent,
        raw: Value::Object(Default::default()),
        read_range: None,
    }
}

/// `parse_hook_input()`. The synthesised payloads come first, exactly as in
/// Python (`payloads.extend(...)` before `payloads.append(main)`), because
/// `_scan_payloads` returns on the *first* blocking payload.
pub fn parse(raw_content: &str) -> Result<Vec<Payload>, Error> {
    if raw_content.trim().is_empty() {
        return Err(Error::Invalid("Error: No input received on stdin".into()));
    }
    let data: Value = serde_json::from_str(raw_content)
        .map_err(|e| Error::Invalid(format!("Error: Failed to parse JSON from stdin: {e}")))?;

    let agent = Agent::detect(&data).ok_or_else(|| Error::Invalid("Unrecognized agent".into()))?;

    let event_name = lookup(&data, &["hook_event_name", "hookEventName"])
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Invalid("Error: couldn't find event type".into()))?;
    let event_type = event_type_from_name(event_name);

    // Resolve Read identifiers against this once, so a relative @-mention and an
    // absolute tool `file_path` for the same file share one cache key.
    let cwd = agent.event_cwd(&data);

    let mut payloads = Vec::new();
    let mut identifier = String::new();
    let mut content = String::new();
    let mut tool = None;
    let mut read_range = None;

    match event_type {
        EventType::UserPrompt => {
            content = lookup_str(&data, &["prompt"]);
            // Files named in the prompt can be read without ever firing a
            // PreToolUse event, so they get their own payloads.
            for path in find_filepaths(&content) {
                payloads.push(read_payload(abs_read_path(&path, &cwd), agent));
            }
        }
        EventType::PreToolUse => {
            let parsed = parse_tool(&data);
            tool = Some(parsed);
            let empty = Value::Object(Default::default());
            let tool_input = data.get("tool_input").unwrap_or(&empty);
            match parsed {
                Tool::Bash => {
                    content = lookup_str(tool_input, &["command"]);
                    identifier = content.clone();
                    payloads.extend(parse_command(&content, agent, &cwd));
                }
                Tool::Read => {
                    identifier = abs_read_path(
                        &lookup_str(tool_input, &["file_path", "filePath", "path"]),
                        &cwd,
                    );
                    read_range = agent.read_range(tool_input);
                }
                _ if is_truthy(tool_input) => {
                    // MCP and unrecognised tool arguments can carry secrets bound
                    // for external servers, so they are scanned as text.
                    content = tool_input.to_string();
                }
                _ => {}
            }
        }
        EventType::PostToolUse => {
            let parsed = parse_tool(&data);
            tool = Some(parsed);
            let empty = Value::Object(Default::default());
            let output =
                lookup(&data, &["tool_output", "tool_response", "tool_result"]).unwrap_or(&empty);
            content = match output {
                // Note the default: with no tool output at all this is the
                // *string* "{}", which is non-empty, so Python does scan it.
                Value::Object(_) | Value::Array(_) => output.to_string(),
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if parsed == Tool::Read {
                let tool_input = data.get("tool_input").unwrap_or(&empty);
                identifier = abs_read_path(
                    &lookup_str(tool_input, &["file_path", "filePath", "path"]),
                    &cwd,
                );
                read_range = agent.read_range(tool_input);
            }
        }
        EventType::Other => {}
    }

    if identifier.is_empty() {
        identifier = sha256_hex(&content);
    }

    payloads.push(Payload {
        event_type,
        tool,
        content,
        identifier,
        agent,
        raw: data,
        read_range,
    });

    // `post_process_payload()`. Only Copilot overrides it: its MCP tools carry
    // no prefix, so they are identified by elimination — a "-" in the tool
    // name, which its own tools (snake_case) never contain.
    if agent == Agent::Copilot {
        for payload in &mut payloads {
            if payload.tool == Some(Tool::Other)
                && lookup_str(&payload.raw, &["tool_name"]).contains('-')
            {
                payload.tool = Some(Tool::Mcp);
            }
        }
    }
    Ok(payloads)
}

/// `_parse_command()`: agents sometimes read a file by shelling out.
fn parse_command(content: &str, agent: Agent, cwd: &str) -> Vec<Payload> {
    if !(content.starts_with("Get-Content ") || content.starts_with("cat ")) {
        return Vec::new();
    }
    let identifier = content.split_once(' ').map(|(_, rest)| rest).unwrap_or("");
    vec![Payload {
        event_type: EventType::PreToolUse,
        tool: Some(Tool::Read),
        content: String::new(),
        identifier: abs_read_path(identifier.trim(), cwd),
        agent,
        raw: Value::Object(Default::default()),
        // `cat`/`Get-Content` read the whole file; a partial read (`sed -n`,
        // `head`) is not treated as a read at all, so there is never a range.
        read_range: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claude(extra: Value) -> Value {
        let mut base = json!({
            "session_id": "abc",
            "transcript_path": "/Users/x/.claude/projects/p/abc.jsonl",
            "cwd": "/tmp",
        });
        for (k, v) in extra.as_object().expect("object") {
            base[k] = v.clone();
        }
        base
    }

    /// GIVEN one payload per supported agent, plus a null transcript path and a
    /// payload with nothing recognisable
    /// WHEN the agent is detected
    /// THEN each agent is identified from its own signature and the last two are
    /// refused rather than guessed at.
    #[test]
    fn detects_each_agent_from_its_own_signature() {
        let cases: [(&str, Value, Option<Agent>); 8] = [
            ("claude", claude(json!({})), Some(Agent::Claude)),
            (
                "codex via turn_id",
                json!({"turn_id": "t1", "hook_event_name": "PreToolUse"}),
                Some(Agent::Codex),
            ),
            (
                "codex via transcript path",
                json!({"session_id": "s", "transcript_path": "/home/u/.codex/x.jsonl"}),
                Some(Agent::Codex),
            ),
            (
                "copilot: exactly the default fields",
                json!({"hook_event_name": "UserPromptSubmitted", "session_id": "s",
                       "timestamp": "2026-01-01", "cwd": "/tmp", "prompt": "hi"}),
                Some(Agent::Copilot),
            ),
            (
                "cursor",
                json!({"cursor_version": "1.7", "hook_event_name": "beforeSubmitPrompt"}),
                Some(Agent::Cursor),
            ),
            (
                "vscode",
                json!({"session_id": "s",
                       "transcript_path": "/x/GitHub.Copilot-Chat/sess.json"}),
                Some(Agent::VsCode),
            ),
            (
                "codex sends transcript_path as null",
                json!({"session_id": "a", "transcript_path": null}),
                None,
            ),
            (
                "nothing recognisable",
                json!({"hook_event_name": "X"}),
                None,
            ),
        ];
        for (label, data, expected) in cases {
            assert_eq!(Agent::detect(&data), expected, "{label}");
        }
    }

    /// GIVEN a Cursor payload, which arrives at a hook configured in Claude Code's
    /// format
    /// WHEN the agent is detected
    /// THEN it is Cursor: detection keys off the payload, never the configuration.
    #[test]
    fn cursor_payload_is_not_mistaken_for_claude() {
        let cursor = json!({
            "cursor_version": "1.7.3",
            "hook_event_name": "beforeSubmitPrompt",
            "conversation_id": "c1",
            "prompt": "hello",
        });
        assert_eq!(Agent::detect(&cursor), Some(Agent::Cursor));
    }

    /// GIVEN a payload carrying exactly Copilot CLI's default fields
    /// WHEN a key is added or removed
    /// THEN it is no longer detected as Copilot: the signature is an exact key set.
    #[test]
    fn copilot_detection_is_an_exact_key_set() {
        let base = json!({"hook_event_name": "PreToolUse", "session_id": "s",
                          "timestamp": "t", "cwd": "/tmp"});
        assert_eq!(Agent::detect(&base), Some(Agent::Copilot));

        let mut with_extra = base.clone();
        with_extra["permission_mode"] = json!("default");
        assert_eq!(Agent::detect(&with_extra), None);

        let mut missing = base.clone();
        missing.as_object_mut().expect("object").shift_remove("cwd");
        assert_eq!(Agent::detect(&missing), None);
    }

    /// GIVEN a payload matching two adapters
    /// WHEN the agent is detected
    /// THEN the earlier one in registry order wins.
    #[test]
    fn detection_follows_registry_order() {
        // Claude before Codex: a .codex transcript path with a claude segment.
        let both = json!({"session_id": "s", "turn_id": "t",
                          "transcript_path": "/home/u/.claude/p/x.jsonl"});
        assert_eq!(Agent::detect(&both), Some(Agent::Claude));
    }

    /// GIVEN a payload whose fields match no agent's signature
    /// WHEN it is parsed
    /// THEN it is rejected as "Unrecognized agent" instead of being scanned blind.
    #[test]
    fn rejects_a_payload_from_no_known_agent() {
        let raw = json!({"hook_event_name": "somethingElse", "prompt": "hi"}).to_string();
        match parse(&raw) {
            Err(Error::Invalid(msg)) => assert_eq!(msg, "Unrecognized agent"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    /// GIVEN a Copilot tool call named `<server>-<tool>` and one in snake_case
    /// WHEN each is parsed
    /// THEN the hyphenated one becomes an MCP tool and the snake_case one does not.
    #[test]
    fn copilot_promotes_hyphenated_tool_names_to_mcp() {
        // post_process_payload: Copilot's MCP tools are "<server>-<tool>", and
        // its own tools are snake_case, so a "-" is the only signal.
        let raw = json!({"hook_event_name": "PreToolUse", "session_id": "s",
                         "timestamp": "t", "cwd": "/tmp",
                         "tool_name": "github-create_issue",
                         "tool_input": {"title": "x"}})
        .to_string();
        let payloads = parse(&raw).expect("parses");
        assert_eq!(payloads[0].agent, Agent::Copilot);
        assert_eq!(payloads[0].tool, Some(Tool::Mcp));

        let raw = json!({"hook_event_name": "PreToolUse", "session_id": "s",
                         "timestamp": "t", "cwd": "/tmp",
                         "tool_name": "report_intent", "tool_input": {"a": 1}})
        .to_string();
        assert_eq!(parse(&raw).expect("parses")[0].tool, Some(Tool::Other));
    }

    /// GIVEN blank input and truncated JSON
    /// WHEN they are parsed
    /// THEN both come back as invalid rather than panicking.
    #[test]
    fn rejects_empty_and_malformed_input() {
        assert!(matches!(parse("   "), Err(Error::Invalid(_))));
        assert!(matches!(parse("{not json"), Err(Error::Invalid(_))));
    }

    /// GIVEN a Claude PreToolUse for `Bash`
    /// WHEN it is parsed
    /// THEN one payload carries the command as its content, and as its identifier —
    /// for Bash the identifier is the command itself, not a hash.
    #[test]
    fn parses_pre_tool_use_bash() {
        let raw = claude(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
        }))
        .to_string();
        let payloads = parse(&raw).expect("parses");
        assert_eq!(payloads.len(), 1);
        let p = &payloads[0];
        assert_eq!(p.event_type, EventType::PreToolUse);
        assert_eq!(p.tool, Some(Tool::Bash));
        assert_eq!(p.content, "echo hello");
        // For Bash the identifier is the command itself, not a hash.
        assert_eq!(p.identifier, "echo hello");
    }

    /// GIVEN a Bash command that is really a file read (`cat /tmp/secrets.env`)
    /// WHEN it is parsed
    /// THEN two payloads come out, the synthesised Read for that path first, so the
    /// file is scanned as a read and not only as a command string.
    #[test]
    fn pre_tool_use_cat_synthesises_a_read_payload_first() {
        let raw = claude(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "cat /tmp/secrets.env"},
        }))
        .to_string();
        let payloads = parse(&raw).expect("parses");
        assert_eq!(payloads.len(), 2);
        assert_eq!(payloads[0].tool, Some(Tool::Read));
        assert_eq!(payloads[0].identifier, "/tmp/secrets.env");
        assert_eq!(payloads[1].tool, Some(Tool::Bash));
    }

    /// GIVEN a PreToolUse for `Read`
    /// WHEN it is parsed
    /// THEN the file path is the identifier and the content is empty: nothing has
    /// been read yet.
    #[test]
    fn pre_tool_use_read_uses_the_path_as_identifier() {
        let raw = claude(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/a.txt"},
        }))
        .to_string();
        let payloads = parse(&raw).expect("parses");
        assert_eq!(payloads[0].tool, Some(Tool::Read));
        assert_eq!(payloads[0].identifier, "/tmp/a.txt");
        assert_eq!(payloads[0].content, "");
    }

    /// GIVEN a PreToolUse for a tool with no special handling
    /// WHEN it is parsed
    /// THEN its serialized `tool_input` is what gets scanned, with the agent's own key
    /// order preserved, and the identifier is that string's sha256.
    #[test]
    fn pre_tool_use_other_tool_scans_serialized_tool_input() {
        let raw = claude(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://x", "token": "abc"},
        }))
        .to_string();
        let payloads = parse(&raw).expect("parses");
        // The agent's own key order is preserved.
        assert_eq!(payloads[0].content, r#"{"url":"https://x","token":"abc"}"#);
        assert_eq!(payloads[0].identifier, sha256_hex(&payloads[0].content));
    }

    /// GIVEN a PostToolUse carrying no `tool_response`
    /// WHEN it is parsed
    /// THEN the content is the string "{}", which is non-empty and therefore scanned.
    #[test]
    fn post_tool_use_without_output_still_scans_the_empty_object() {
        let raw = claude(json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        }))
        .to_string();
        let payloads = parse(&raw).expect("parses");
        // `lookup(..., {})` then serialising it: the *string* "{}", which is
        // non-empty, so it is scanned.
        assert_eq!(payloads[0].content, "{}");
    }

    /// GIVEN a PostToolUse for `Read` with a response body
    /// WHEN it is parsed
    /// THEN the identifier is still the file path, and the serialized response is the
    /// content to scan.
    #[test]
    fn post_tool_use_read_keeps_the_file_path_identifier() {
        let raw = claude(json!({
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/a.txt"},
            "tool_response": {"content": "hello"},
        }))
        .to_string();
        let payloads = parse(&raw).expect("parses");
        assert_eq!(payloads[0].identifier, "/tmp/a.txt");
        assert_eq!(payloads[0].content, r#"{"content":"hello"}"#);
    }

    /// GIVEN a tool named `mcp__<server>__<tool>`
    /// WHEN it is parsed
    /// THEN it is classified as the MCP tool.
    #[test]
    fn mcp_tool_names_map_to_the_mcp_tool() {
        let raw = claude(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__github__create_issue",
            "tool_input": {"title": "x"},
        }))
        .to_string();
        assert_eq!(parse(&raw).expect("parses")[0].tool, Some(Tool::Mcp));
    }

    /// GIVEN a prompt mentioning a bare `@path` and a quoted `@"a b.txt"`
    /// WHEN it is parsed
    /// THEN each mention becomes its own payload, canonicalized against the event cwd
    /// so it matches a tool's absolute path, and the prompt payload comes last.
    #[test]
    fn user_prompt_extracts_at_paths() {
        let raw = claude(json!({
            "hook_event_name": "UserPromptSubmit",
            "prompt": "look at @src/main.rs and @\"a b.txt\" please.",
        }))
        .to_string();
        let payloads = parse(&raw).expect("parses");
        let ids: Vec<_> = payloads.iter().map(|p| p.identifier.as_str()).collect();
        // Canonicalized against the event cwd ("/tmp"), so a relative @-mention
        // resolves to the same identifier a tool's absolute path would.
        assert!(ids.contains(&"/tmp/src/main.rs"), "{ids:?}");
        assert!(ids.contains(&"/tmp/a b.txt"), "{ids:?}");
        // The prompt payload itself is last.
        assert_eq!(
            payloads.last().expect("non-empty").event_type,
            EventType::UserPrompt
        );
    }

    fn read_range_of(raw: &Value) -> Option<ReadRange> {
        parse(&raw.to_string()).expect("parses")[0].read_range
    }

    /// GIVEN a Read payload from each agent
    /// WHEN its read range is resolved
    /// THEN each agent's own convention is honoured, and an absent or unusable
    /// parameter means the whole file — reading too little lets content reach the
    /// model unscanned.
    #[test]
    fn read_range_per_agent() {
        let claude_read = |extra: Value| {
            let mut input = json!({"file_path": "/tmp/a.txt"});
            for (k, v) in extra.as_object().expect("object") {
                input[k] = v.clone();
            }
            claude(json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": input,
            }))
        };
        assert_eq!(
            read_range_of(&claude_read(json!({"offset": 10, "limit": 5}))),
            Some((10, Some(14)))
        );
        // Open-ended: scan to the end, not to some assumed default cap.
        assert_eq!(
            read_range_of(&claude_read(json!({"offset": 500}))),
            Some((500, None))
        );
        // No offset means "from the first line", not "from nowhere".
        assert_eq!(
            read_range_of(&claude_read(json!({"limit": 5}))),
            Some((1, Some(5)))
        );
        assert_eq!(read_range_of(&claude_read(json!({}))), None);
        // Nonsense values fall back to the whole file rather than to a window.
        assert_eq!(
            read_range_of(&claude_read(json!({"offset": 0, "limit": -3}))),
            None
        );
        assert_eq!(
            read_range_of(&claude_read(json!({"offset": "10", "limit": 1.5}))),
            None
        );

        // VS Code: startLine/endLine, 1-based inclusive.
        let vscode = json!({
            "session_id": "s",
            "transcript_path": "/x/GitHub.copilot-chat/sess.jsonl",
            "hook_event_name": "PreToolUse",
            "tool_name": "read_file",
            "tool_input": {"filePath": "/tmp/a.txt", "startLine": 20, "endLine": 24},
        });
        assert_eq!(read_range_of(&vscode), Some((20, Some(24))));

        // Cursor mimics Claude's payload but has never been seen sending a range.
        let cursor = json!({
            "cursor_version": "2.5.25",
            "hook_event_name": "preToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/a.txt", "offset": 10, "limit": 5},
        });
        assert_eq!(read_range_of(&cursor), None);

        // Copilot CLI's `view` carries only `path`.
        let copilot = json!({
            "hook_event_name": "PreToolUse", "session_id": "s",
            "timestamp": "t", "cwd": "/tmp",
            "tool_name": "view", "tool_input": {"path": "/tmp/a.txt", "offset": 10},
        });
        assert_eq!(read_range_of(&copilot), None);

        // Codex reads by shelling out; `cat` reads the whole file.
        let codex = json!({
            "turn_id": "t1", "hook_event_name": "PreToolUse",
            "tool_name": "shell", "tool_input": {"command": "cat /tmp/a.txt"},
        });
        assert_eq!(read_range_of(&codex), None);
    }

    /// GIVEN a Read at PreToolUse and then at PostToolUse
    /// WHEN their ranges are resolved
    /// THEN they are the same window, which is what lets one verdict answer both.
    #[test]
    fn post_tool_use_read_carries_the_same_range_as_pre() {
        let payload = |event: &str| {
            claude(json!({
                "hook_event_name": event,
                "tool_name": "Read",
                "tool_input": {"file_path": "/tmp/a.txt", "offset": 10, "limit": 5},
                "tool_response": {"content": "whatever the agent got back"},
            }))
        };
        assert_eq!(read_range_of(&payload("PreToolUse")), Some((10, Some(14))));
        assert_eq!(read_range_of(&payload("PostToolUse")), Some((10, Some(14))));
    }

    /// GIVEN a ten line fixture
    /// WHEN a line range is sliced
    /// THEN one extra line is taken on each side, clamped at both ends exactly as a
    /// Python slice is, and a range past the end yields nothing.
    #[test]
    fn line_slice_takes_one_line_of_slack_on_each_side() {
        let content = (1..=10)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            line_slice(&content, (3, Some(5))),
            "line 2\nline 3\nline 4\nline 5\nline 6"
        );
        // Clamped at both ends, exactly as a Python slice is.
        assert_eq!(line_slice(&content, (1, Some(2))), "line 1\nline 2\nline 3");
        assert_eq!(line_slice(&content, (9, None)), "line 8\nline 9\nline 10");
        assert_eq!(line_slice(&content, (99, Some(120))), "");
    }

    /// GIVEN an LF and a CRLF fixture
    /// WHEN a range of each is sliced
    /// THEN the slice occurs verbatim in the file, and a vertical tab does not
    /// shift the line numbering.
    #[test]
    fn line_slice_is_a_verbatim_extract_whatever_the_terminator() {
        for newline in ["\n", "\r\n"] {
            let content = (1..=10)
                .map(|i| format!("line {i}"))
                .collect::<Vec<_>>()
                .join(newline);
            let slice = line_slice(&content, (3, Some(5)));
            assert!(content.contains(&slice), "{newline:?}: {slice:?}");
            assert_eq!(slice.lines().count(), 5, "{newline:?}");
        }
        // Line numbering must not move on a vertical tab or form feed, which
        // `splitlines()`/`str::lines()` would treat as line breaks.
        assert_eq!(line_slice("a\x0bb\nc\nd\ne", (3, Some(3))), "c\nd\ne");
    }

    /// GIVEN prompts with a `@file:` mention ending in a dot, and an email address
    /// WHEN file paths are extracted
    /// THEN the prefix and trailing dot are stripped from the path, and the email is
    /// not mistaken for one — its `@` is not preceded by `\W` or start of string.
    #[test]
    fn file_path_regex_matches_the_python_cases() {
        assert_eq!(find_filepaths("no paths here"), BTreeSet::new());
        // Trailing dot is stripped, "file:" prefix is dropped.
        assert!(find_filepaths("see @file:foo/bar.py.").contains("foo/bar.py"));
        // An email address is not a path: the @ is not preceded by \W or ^.
        assert!(!find_filepaths("mail me at a@b.com").contains("b.com"));
    }

    /// GIVEN absolute, relative and empty identifiers against various cwds
    /// WHEN each read path is resolved
    /// THEN it matches Python's `abspath(join(...))`: `..` resolved lexically with no
    /// filesystem access, `.` dropped, repeated `/` squeezed, empties left alone.
    #[test]
    fn abs_read_path_matches_python_abspath_join() {
        // Absolute identifier: cwd is dropped, path returned unchanged.
        assert_eq!(abs_read_path("/tmp/a.txt", "/home/user"), "/tmp/a.txt");
        // Relative identifier: joined onto cwd, absolute.
        assert_eq!(
            abs_read_path("src/creds.env", "/home/user/proj"),
            "/home/user/proj/src/creds.env"
        );
        // Empty cwd or empty identifier: returned unchanged.
        assert_eq!(abs_read_path("src/a.txt", ""), "src/a.txt");
        assert_eq!(abs_read_path("", "/home/user"), "");
        // `..` is resolved lexically (no filesystem, no symlinks).
        assert_eq!(
            abs_read_path("../bar/x.txt", "/home/user/foo"),
            "/home/user/bar/x.txt"
        );
        // `.` segments dropped and repeated `/` squeezed.
        assert_eq!(
            abs_read_path("./a//b/x.txt", "/home/user"),
            "/home/user/a/b/x.txt"
        );
    }

    /// GIVEN a relative `@`-mention and an absolute tool `file_path` for one file
    /// WHEN both are parsed
    /// THEN they resolve to the same identifier, so one verdict-cache key covers
    /// both and the file is scanned once.
    #[test]
    fn prompt_mention_and_tool_read_share_one_identifier() {
        let prompt = claude(json!({
            "cwd": "/home/user/proj",
            "hook_event_name": "UserPromptSubmit",
            "prompt": "check @src/creds.env",
        }))
        .to_string();
        let mention = parse(&prompt).expect("parses");
        let ids: Vec<_> = mention.iter().map(|p| p.identifier.as_str()).collect();
        assert!(ids.contains(&"/home/user/proj/src/creds.env"), "{ids:?}");

        let read = claude(json!({
            "cwd": "/home/user/proj",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/home/user/proj/src/creds.env"},
        }))
        .to_string();
        assert_eq!(
            parse(&read).expect("parses")[0].identifier,
            "/home/user/proj/src/creds.env"
        );
    }

    /// GIVEN a Cursor event, which reports `workspace_roots` instead of `cwd`
    /// WHEN its working directory is read
    /// THEN the first root is used, and no roots means "unknown".
    #[test]
    fn cursor_event_cwd_reads_workspace_roots() {
        let cursor = json!({
            "cursor_version": "2.5.25",
            "workspace_roots": ["/home/user/foo"],
            "hook_event_name": "beforeSubmitPrompt",
        });
        assert_eq!(Agent::Cursor.event_cwd(&cursor), "/home/user/foo");
        // No roots: "" (unknown), so abs_read_path leaves identifiers untouched.
        assert_eq!(Agent::Cursor.event_cwd(&json!({})), "");
    }
}
