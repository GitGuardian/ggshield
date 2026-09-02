//! Hook payload parsing and agent detection. Mirrors `parse_hook_input()`
//! and `_detect_agent()` in `ggshield/verticals/ai/hooks.py`.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
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

/// The assistants ggshield supports, in the registry order of `AGENTS`
/// (agents/__init__.py). Detection takes the FIRST match, so the order matters.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Agent {
    Vibe,
    Claude,
    Codex,
    Copilot,
    Cursor,
    VsCode,
    Kiro,
}

pub const AGENTS: [Agent; 7] = [
    Agent::Vibe,
    Agent::Claude,
    Agent::Codex,
    Agent::Copilot,
    Agent::Cursor,
    Agent::VsCode,
    // Last: Kiro keys on event names other agents share (`PreToolUse` and
    // friends), so it is the broadest matcher of the seven and every exact one
    // gets first refusal.
    Agent::Kiro,
];

impl Agent {
    /// Sent as the `GGShield-Agent-Name` header.
    pub fn name(self) -> &'static str {
        match self {
            Agent::Vibe => "vibe",
            Agent::Claude => "claude-code",
            Agent::Codex => "codex",
            Agent::Copilot => "copilot",
            Agent::Cursor => "cursor",
            Agent::VsCode => "vscode",
            Agent::Kiro => "kiro",
        }
    }

    /// Used in the desktop notification text.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn display_name(self) -> &'static str {
        match self {
            Agent::Vibe => "Mistral Vibe",
            Agent::Claude => "Claude Code",
            Agent::Codex => "Codex",
            Agent::Copilot => "Copilot CLI",
            Agent::Cursor => "Cursor",
            Agent::VsCode => "VSCode",
            Agent::Kiro => "Kiro",
        }
    }

    /// `is_caller()`. The shapes overlap enough that a near-miss misroutes a
    /// payload, i.e. emits a verdict in a schema the caller ignores.
    fn is_caller(self, data: &Value) -> bool {
        // `... or ""`: a null and a missing key both read as the empty string.
        let transcript = data
            .get("transcript_path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match self {
            // Vibe's snake_case event names are exact, which is why it is
            // registered first: a Vibe transcript path under /home/claude would
            // otherwise be claimed by Claude's "claude" substring heuristic below.
            Agent::Vibe => matches!(
                data.get("hook_event_name").and_then(Value::as_str),
                Some("pre_tool" | "post_tool" | "post_agent")
            ),
            Agent::Claude => data.get("session_id").is_some() && transcript.contains("claude"),
            Agent::Codex => {
                data.get("turn_id").is_some() || transcript.to_lowercase().contains(".codex")
            }
            // Copilot CLI emits only the default fields, which is itself the
            // signature: an exact key-set match once the optional ones are gone.
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
            // Kiro CLI spells its triggers in camelCase and the Kiro IDE in
            // PascalCase; neither surface sends anything else identifying.
            Agent::Kiro => {
                const TRIGGERS: [&str; 15] = [
                    "userPromptSubmit",
                    "UserPromptSubmit",
                    "preToolUse",
                    "PreToolUse",
                    "postToolUse",
                    "PostToolUse",
                    "agentSpawn",
                    "SessionStart",
                    "stop",
                    "Stop",
                    "PreTaskExec",
                    "PostTaskExec",
                    "PostFileCreate",
                    "PostFileSave",
                    "PostFileDelete",
                ];
                // Several of those spellings are shared with Claude, Cursor,
                // Codex, Copilot CLI and Junie CLI, so the event name alone
                // would let Kiro claim their payloads. These keys are what each
                // of them sends and Kiro never does. `project_path` is Junie's,
                // which mirrors Claude Code's wire protocol deliberately and so
                // has no marker of its own either.
                const FOREIGN_KEYS: [&str; 5] = [
                    "transcript_path",
                    "cursor_version",
                    "turn_id",
                    "timestamp",
                    "project_path",
                ];
                let Some(name) = data.get("hook_event_name").and_then(Value::as_str) else {
                    return false;
                };
                TRIGGERS.contains(&name) && FOREIGN_KEYS.iter().all(|key| data.get(key).is_none())
            }
        }
    }

    /// `_detect_agent()`. First match in registry order wins.
    pub fn detect(data: &Value) -> Option<Agent> {
        AGENTS.into_iter().find(|agent| agent.is_caller(data))
    }

    /// The working directory the event happened in, used to resolve a relative
    /// Read path to the absolute identifier a tool call would produce, so both
    /// share one verdict-cache key — and as the project root the default
    /// exclusions are tested relative to. "" when unknown.
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
    /// `None` (the whole file) is what an absent or unusable parameter resolves
    /// to: reading too little lets content reach the model unscanned.
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
            // which can be absent. Read's own cap on an open-ended read is not
            // in the payload, so it is not subtracted here.
            Agent::Claude => {
                let first = positive("offset").unwrap_or(1);
                match positive("limit") {
                    // Both come from `tool_input`, so both are prompt-controlled:
                    // `first + limit` wrapping would yield an empty slice, i.e. a
                    // read nothing was scanned for. Saturating means "to the end".
                    Some(limit) => Some((first, Some(first.saturating_add(limit - 1)))),
                    None if first == 1 => None,
                    None => Some((first, None)),
                }
            }
            // VS Code's read_file: `startLine`/`endLine`, 1-based inclusive.
            Agent::VsCode => {
                let first = positive("startLine").unwrap_or(1);
                let last = positive("endLine");
                if first == 1 && last.is_none() {
                    None
                } else {
                    Some((first, last))
                }
            }
            // No range ever seen from these five: Copilot CLI's `view` carries
            // only `path`, Cursor's Read has no range keys, Codex shells out,
            // Vibe's `read_file` carries only `path`. Kiro's IDE reader does
            // carry `offset` and `limit`, but nothing establishes whether they
            // mean what the same two names mean to Claude, and a range read the
            // wrong way round scans past the lines the agent asked for while
            // leaving the ones it gets unscanned. The whole file is the safe
            // answer until a payload settles it.
            Agent::Codex | Agent::Copilot | Agent::Cursor | Agent::Vibe | Agent::Kiro => None,
        }
    }
}

/// `(first, last)`, 1-based and inclusive, `None` for "to the end of the file".
pub type ReadRange = (u64, Option<u64>);

/// `line_slice()`: lines `first` to `last` of `content`, 1-based and inclusive.
///
/// Split on "\n" only, the way agents number lines: `str::lines()` (and Python's
/// `splitlines()`) also break on vertical tab and friends, which would shift every
/// line number after the first such character. A CRLF file keeps its "\r".
///
/// One line of slack on each side, because agents document their ranges in their
/// own conventions and a missing line lets content reach the model unscanned.
pub fn line_slice(content: &str, (first, last): ReadRange) -> String {
    let lines: Vec<&str> = content.split('\n').collect();
    // Python's `lines[max(0, first - 2) : None if last is None else last + 1]`,
    // clamped at both ends the way a Python slice is.
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
    /// The `cwd` the identifier was resolved against, see `Agent::event_cwd()`.
    pub cwd: String,

    /// The original hook JSON, `{}` for synthesised payloads as in Python. Only
    /// read for the desktop notification's command text.
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
        // Copilot CLI's and Cursor's spellings of the prompt event.
        "userpromptsubmit" | "userpromptsubmitted" | "beforesubmitprompt" => EventType::UserPrompt,
        // "pre_tool"/"post_tool" are Vibe's spelling. Its "post_agent" is
        // deliberately absent: it falls through to EventType::Other, which
        // carries no content to scan.
        "pretooluse" | "pre_tool" => EventType::PreToolUse,
        "posttooluse" | "post_tool" => EventType::PostToolUse,
        _ => EventType::Other,
    }
}

fn parse_tool(data: &Value) -> Tool {
    let name = lookup_str(data, &["tool_name"]).to_lowercase();
    // The Kiro IDE's `mcp_{server}_{tool}` already matches the prefix rule; the
    // Kiro CLI writes the same call as `@{server}/{tool}`.
    if name.starts_with("mcp") || name.starts_with('@') {
        return Tool::Mcp;
    }
    match name.as_str() {
        // `git_bash` and `powershell` are Vibe's other two shells; mapping them to
        // Bash is what gets their command parsed for file reads.
        // `execute_bash`, its `execute_cmd` alias and `execute_pwsh` are Kiro's.
        "shell" | "bash" | "git_bash" | "powershell" | "run_in_terminal" | "execute_bash"
        | "execute_cmd" | "execute_pwsh" => Tool::Bash,
        // `fs_read` is Kiro's CLI reader, `read_file` its IDE one. Its plural
        // `read_files` is deliberately absent: it takes several paths in an
        // unverified shape, and a Read payload whose path lookup finds nothing
        // scans nothing. Left generic, the response it returns is still scanned.
        "read" | "read_file" | "view" | "fs_read" => Tool::Read,
        // Kiro's writers (`fs_write`, `str_replace`, `fs_append`) belong here on
        // purpose: the generic branch scans their `tool_input`, which is what
        // carries the content about to be written.
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
        // _FILE_PATH_REGEX from hooks.py, with re.MULTILINE as the (?m) flag.
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

/// `find_filepaths()`. Sorted, unlike Python's `set`, so which payload blocks
/// first is deterministic.
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

/// Resolve a Read identifier against the event's `cwd`, so a relative @-mention
/// and an absolute tool `file_path` for one file share a single verdict-cache key.
///
/// Lexical, like `os.path.abspath(os.path.join(cwd, identifier))`: no filesystem
/// access and no symlink resolution. `std::path` supplies the platform's own
/// notion of "absolute" and of a separator, which is what `os.path` does — a
/// POSIX-only test treats `C:\...` and `\\host\share\...` as relative and builds
/// `C:\proj/C:\Users\...`, a path that exists nowhere, so the file is never read
/// and the payload text is scanned in its place.
fn abs_read_path(identifier: &str, cwd: &str) -> String {
    if identifier.is_empty() || cwd.is_empty() {
        return identifier.to_string();
    }
    // `Path::join` already implements `os.path.join`: an absolute (or, on
    // Windows, root-relative) second argument replaces the first.
    normpath(&Path::new(cwd).join(identifier))
}

/// Lexical `os.path.normpath`: squeeze repeated separators, drop `.`, resolve
/// `..`, and render with the platform separator. No filesystem access.
fn normpath(path: &Path) -> String {
    let mut out = PathBuf::new();
    let mut rooted = false;
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match out.components().next_back() {
                Some(Component::Normal(_)) => {
                    out.pop();
                }
                // As normpath: a leading `..` is kept on a relative path, and
                // dropped past the root of an absolute one.
                _ if !rooted => out.push(".."),
                _ => {}
            },
            other => {
                rooted |= matches!(other, Component::RootDir | Component::Prefix(_));
                out.push(other.as_os_str());
            }
        }
    }
    if out.as_os_str().is_empty() {
        return ".".to_string();
    }
    out.to_string_lossy().into_owned()
}

fn read_payload(identifier: String, agent: Agent, cwd: &str) -> Payload {
    Payload {
        event_type: EventType::UserPrompt,
        tool: Some(Tool::Read),
        content: String::new(),
        identifier,
        agent,
        cwd: cwd.to_string(),
        raw: Value::Object(Default::default()),
        read_range: None,
    }
}

/// `parse_hook_input()`. The synthesised payloads come first, as in Python
/// (`payloads.extend(...)` before `payloads.append(main)`), because
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

    // Resolved once: see `abs_read_path`.
    let cwd = agent.event_cwd(&data);

    let mut payloads = Vec::new();
    let mut identifier = String::new();
    let mut content = String::new();
    let mut tool = None;
    let mut read_range = None;

    match event_type {
        EventType::UserPrompt => {
            content = lookup_str(&data, &["prompt"]);
            // Files named in the prompt can be read without a PreToolUse event.
            for path in find_filepaths(&content) {
                payloads.push(read_payload(abs_read_path(&path, &cwd), agent, &cwd));
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
                    // A reader that names its files somewhere else entirely, see
                    // `read_operations`. The payload built here then carries no
                    // identifier and no content, so it is scanned for nothing.
                    if identifier.is_empty() {
                        payloads.extend(read_operations(tool_input, agent, &cwd));
                    }
                }
                // MCP and unrecognised tool arguments can carry secrets bound
                // for external servers, so they are scanned as text.
                _ if is_truthy(tool_input) => content = tool_input.to_string(),
                _ => {}
            }
        }
        EventType::PostToolUse => {
            let parsed = parse_tool(&data);
            tool = Some(parsed);
            let empty = Value::Object(Default::default());
            let empty_text = Value::String(String::new());
            let output =
                lookup(&data, &["tool_output", "tool_response", "tool_result"]).unwrap_or(&empty);
            // Vibe nulls the structured output when the tool call failed and
            // leaves the text the model sees in `tool_output_text`. Without this
            // the scanned content would be the literal "null".
            let output = if output.is_null() {
                match data.get("tool_output_text") {
                    Some(text) if !text.is_null() => text,
                    _ => &empty_text,
                }
            } else {
                output
            };
            content = match output {
                // With no tool output at all this is the *string* "{}", which is
                // non-empty, so Python does scan it.
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
                if identifier.is_empty() {
                    // A reader that names its file under `operations`. Recovering
                    // it is what lets `secret.ignored_paths` and the verdict cache
                    // see a path at all; the response body alone gives them a
                    // hash. Only a single-file read has one path to answer with.
                    let paths = read_operation_paths(tool_input);
                    if let [path] = paths[..] {
                        identifier = abs_read_path(path, &cwd);
                    }
                }
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
        cwd,
        raw: data,
        read_range,
    });

    // `post_process_payload()`. Two agents override it, both because their MCP
    // tool names carry no `mcp` prefix for `parse_tool()` to key off.
    match agent {
        // Copilot's MCP tools are "<server>-<tool>", and its own tools are
        // snake_case, so a "-" is the only signal.
        Agent::Copilot => {
            for payload in &mut payloads {
                if payload.tool == Some(Tool::Other)
                    && lookup_str(&payload.raw, &["tool_name"]).contains('-')
                {
                    payload.tool = Some(Tool::Mcp);
                }
            }
        }
        // Vibe's are "{server}_{tool}", which only its configured server names
        // can distinguish. See `vibe::post_process`.
        Agent::Vibe => {
            for payload in &mut payloads {
                crate::vibe::post_process(payload);
            }
        }
        _ => {}
    }
    Ok(payloads)
}

/// The file paths a read tool names under `operations`, in order.
fn read_operation_paths(tool_input: &Value) -> Vec<&str> {
    tool_input
        .get("operations")
        .and_then(Value::as_array)
        .map(|operations| {
            operations
                .iter()
                .filter_map(|operation| operation.get("path").and_then(Value::as_str))
                .filter(|path| !path.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// The files a read tool names in an `operations` list rather than in a `path` of
/// its own, one payload each.
///
/// Kiro's `fs_read` takes `{"operations": [{"mode": "Line", "path": "..."}, ...]}`,
/// so a single call can expose several files and none of them is reachable through
/// the usual `file_path`/`path` lookup. Every entry is a file about to reach the
/// model, so every entry is scanned; a call whose paths cannot be read at all
/// leaves nothing behind, which is what an unrecognised shape must not do
/// silently.
fn read_operations(tool_input: &Value, agent: Agent, cwd: &str) -> Vec<Payload> {
    read_operation_paths(tool_input)
        .into_iter()
        .map(|path| Payload {
            event_type: EventType::PreToolUse,
            tool: Some(Tool::Read),
            content: String::new(),
            identifier: abs_read_path(path, cwd),
            agent,
            cwd: cwd.to_string(),
            raw: Value::Object(Default::default()),
            read_range: None,
        })
        .collect()
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
        cwd: cwd.to_string(),
        raw: Value::Object(Default::default()),
        // `cat`/`Get-Content` read the whole file, and a partial read (`sed -n`,
        // `head`) is not treated as a read at all.
        read_range: None,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A POSIX fixture path as `abs_read_path` renders it on this platform, so one
    /// expectation covers Windows too (where `os.path` uses `\\`).
    fn native(path: &str) -> String {
        normpath(Path::new(path))
    }

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
    /// THEN each is identified from its own signature and the last two are refused.
    #[test]
    fn detects_each_agent_from_its_own_signature() {
        let cases: [(&str, Value, Option<Agent>); 10] = [
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
                "kiro cli",
                json!({"hook_event_name": "preToolUse", "cwd": "/p",
                       "tool_name": "fs_write", "tool_input": {"command": "create"}}),
                Some(Agent::Kiro),
            ),
            (
                "kiro ide",
                json!({"session_id": "sess_1", "hook_event_name": "PreToolUse",
                       "cwd": "/p", "tool_name": "str_replace", "tool_input": {}}),
                Some(Agent::Kiro),
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

    fn vibe(extra: Value) -> Value {
        let mut base = json!({
            "session_id": "session-123",
            "transcript_path": "/home/user/.vibe/logs/session-123.jsonl",
            "cwd": "/home/user/project",
        });
        for (k, v) in extra.as_object().expect("object") {
            base[k] = v.clone();
        }
        base
    }

    /// GIVEN a Vibe payload whose transcript path also contains "claude"
    /// WHEN the agent is detected
    /// THEN it is Vibe: its snake_case event names are exact, so it is registered
    /// ahead of Claude's transcript-path substring heuristic.
    #[test]
    fn vibe_wins_over_claude_when_the_path_contains_claude() {
        let data = json!({
            "session_id": "session-123",
            "transcript_path": "/home/claude/.vibe/logs/session-123.jsonl",
            "cwd": "/home/user/project",
            "hook_event_name": "pre_tool",
            "tool_name": "bash",
            "tool_input": {"command": "whoami"},
        });
        assert_eq!(Agent::detect(&data), Some(Agent::Vibe));
    }

    /// GIVEN each of Vibe's three event names, and one it does not emit
    /// WHEN the agent is detected
    /// THEN only its own three identify it — detection keys on the event name
    /// alone, so a near-miss must not be claimed.
    #[test]
    fn vibe_is_detected_from_its_event_names_alone() {
        for event in ["pre_tool", "post_tool", "post_agent"] {
            let data = json!({"hook_event_name": event});
            assert_eq!(Agent::detect(&data), Some(Agent::Vibe), "{event}");
        }
        assert_eq!(
            Agent::detect(&json!({"hook_event_name": "pre_tool_use"})),
            None
        );
    }

    /// GIVEN Vibe's `post_agent` event
    /// WHEN it is parsed
    /// THEN Vibe is recognised but the event maps to no type, so there is nothing
    /// to scan — exactly as in Python.
    #[test]
    fn vibe_post_agent_parses_as_an_other_event() {
        let raw = vibe(json!({"hook_event_name": "post_agent"})).to_string();
        let payloads = parse(&raw).expect("parses");
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0].agent, Agent::Vibe);
        assert_eq!(payloads[0].event_type, EventType::Other);
        assert_eq!(payloads[0].content, "");
    }

    /// GIVEN a `cat` command from each of Vibe's three shells
    /// WHEN it is parsed
    /// THEN all three are Bash, so the command is parsed for the file read rather
    /// than scanned as an opaque tool input.
    #[test]
    fn vibe_shell_tools_are_all_bash() {
        for tool_name in ["bash", "git_bash", "powershell"] {
            let raw = vibe(json!({
                "hook_event_name": "pre_tool",
                "tool_name": tool_name,
                "tool_input": {"command": "cat /tmp/secret.txt"},
            }))
            .to_string();
            let payloads = parse(&raw).expect("parses");
            assert_eq!(
                payloads.last().expect("non-empty").tool,
                Some(Tool::Bash),
                "{tool_name}"
            );
            // The command names a file, so it is also scanned as a read.
            assert!(
                payloads.iter().any(|p| p.tool == Some(Tool::Read)),
                "{tool_name}: no synthesised read"
            );
        }
    }

    /// GIVEN a failed Vibe tool call, which reports a null structured output
    /// WHEN it is parsed
    /// THEN the text the model actually sees is scanned, not the literal "null".
    #[test]
    fn vibe_failed_post_tool_scans_the_output_text() {
        let raw = vibe(json!({
            "hook_event_name": "post_tool",
            "tool_name": "bash",
            "tool_input": {"command": "failing-command"},
            "tool_status": "failure",
            "tool_output": null,
            "tool_output_text": "failure output",
        }))
        .to_string();
        let payloads = parse(&raw).expect("parses");
        assert_eq!(payloads[0].event_type, EventType::PostToolUse);
        assert_eq!(payloads[0].content, "failure output");

        // Null output and no text either: nothing to scan, still not "null".
        let raw = vibe(json!({
            "hook_event_name": "post_tool",
            "tool_name": "bash",
            "tool_input": {"command": "x"},
            "tool_output": null,
        }))
        .to_string();
        assert_eq!(parse(&raw).expect("parses")[0].content, "");
    }

    /// GIVEN a successful Vibe `read_file`, which names the file in `path`
    /// WHEN it is parsed
    /// THEN the path is the identifier and the structured output is the content,
    /// so the null fallback does not disturb the normal case.
    #[test]
    fn vibe_post_tool_read_uses_the_path_and_the_structured_output() {
        let raw = vibe(json!({
            "hook_event_name": "post_tool",
            "tool_name": "read_file",
            "tool_input": {"path": "/tmp/secret.txt"},
            "tool_status": "success",
            "tool_output": {"content": "file content"},
            "tool_output_text": "file content",
        }))
        .to_string();
        let payloads = parse(&raw).expect("parses");
        assert_eq!(payloads[0].tool, Some(Tool::Read));
        assert_eq!(payloads[0].identifier, native("/tmp/secret.txt"));
        assert_eq!(payloads[0].content, r#"{"content":"file content"}"#);
        // Vibe's read_file carries no range: the whole file is scanned.
        assert_eq!(payloads[0].read_range, None);
    }

    /// GIVEN a Cursor payload arriving at a Claude-Code-format hook
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
    /// THEN it is rejected as "Unrecognized agent".
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
    /// THEN one payload carries the command as both content and identifier.
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
        assert_eq!(p.identifier, "echo hello");
    }

    /// GIVEN a Bash command that is really a file read (`cat /tmp/secrets.env`)
    /// WHEN it is parsed
    /// THEN two payloads come out, the synthesised Read for that path first.
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
        assert_eq!(payloads[0].identifier, native("/tmp/secrets.env"));
        assert_eq!(payloads[1].tool, Some(Tool::Bash));
    }

    /// GIVEN a PreToolUse for `Read`
    /// WHEN it is parsed
    /// THEN the file path is the identifier and the content is empty.
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
        assert_eq!(payloads[0].identifier, native("/tmp/a.txt"));
        assert_eq!(payloads[0].content, "");
    }

    /// GIVEN a PreToolUse for a tool with no special handling
    /// WHEN it is parsed
    /// THEN its serialized `tool_input` is scanned, with the agent's own key order
    /// preserved, and the identifier is that string's sha256.
    #[test]
    fn pre_tool_use_other_tool_scans_serialized_tool_input() {
        let raw = claude(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "WebFetch",
            "tool_input": {"url": "https://x", "token": "abc"},
        }))
        .to_string();
        let payloads = parse(&raw).expect("parses");
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
        assert_eq!(payloads[0].content, "{}");
    }

    /// GIVEN a PostToolUse for `Read` with a response body
    /// WHEN it is parsed
    /// THEN the identifier is still the file path and the serialized response is
    /// the content to scan.
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
        assert_eq!(payloads[0].identifier, native("/tmp/a.txt"));
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
    /// THEN each mention becomes its own payload, canonicalized against the event
    /// cwd, and the prompt payload comes last.
    #[test]
    fn user_prompt_extracts_at_paths() {
        let raw = claude(json!({
            "hook_event_name": "UserPromptSubmit",
            "prompt": "look at @src/main.rs and @\"a b.txt\" please.",
        }))
        .to_string();
        let payloads = parse(&raw).expect("parses");
        let ids: Vec<_> = payloads.iter().map(|p| p.identifier.as_str()).collect();
        assert!(
            ids.contains(&native("/tmp/src/main.rs").as_str()),
            "{ids:?}"
        );
        assert!(ids.contains(&native("/tmp/a b.txt").as_str()), "{ids:?}");
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
    /// parameter means the whole file.
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

        let copilot = json!({
            "hook_event_name": "PreToolUse", "session_id": "s",
            "timestamp": "t", "cwd": "/tmp",
            "tool_name": "view", "tool_input": {"path": "/tmp/a.txt", "offset": 10},
        });
        assert_eq!(read_range_of(&copilot), None);

        let codex = json!({
            "turn_id": "t1", "hook_event_name": "PreToolUse",
            "tool_name": "shell", "tool_input": {"command": "cat /tmp/a.txt"},
        });
        assert_eq!(read_range_of(&codex), None);
    }

    /// GIVEN a Read whose prompt-controlled `offset` and `limit` sum past `u64::MAX`
    /// WHEN the range is resolved and sliced
    /// THEN it runs to the end of the file. Wrapping turned the pair into a range
    /// ending *before* it starts, i.e. an empty document, i.e. an unscanned read.
    #[test]
    fn read_range_never_wraps() {
        let raw = claude(json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/a.txt", "offset": 2, "limit": u64::MAX},
        }));
        assert_eq!(read_range_of(&raw), Some((2, Some(u64::MAX))));

        let content = (1..=5)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(line_slice(&content, (2, Some(u64::MAX))).lines().count(), 5);
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
    /// THEN one extra line is taken on each side, clamped as a Python slice is,
    /// and a range past the end yields nothing.
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
    /// THEN the prefix and trailing dot are stripped, and the email is not
    /// mistaken for a path.
    #[test]
    fn file_path_regex_matches_the_python_cases() {
        assert_eq!(find_filepaths("no paths here"), BTreeSet::new());
        assert!(find_filepaths("see @file:foo/bar.py.").contains("foo/bar.py"));
        assert!(!find_filepaths("mail me at a@b.com").contains("b.com"));
    }

    /// GIVEN absolute, relative and empty identifiers against various cwds
    /// WHEN each read path is resolved
    /// THEN it matches `abspath(join(...))`: `..` resolved lexically, `.` dropped,
    /// repeated separators squeezed, empties left alone.
    #[test]
    #[cfg(unix)]
    fn abs_read_path_matches_python_abspath_join() {
        assert_eq!(abs_read_path("/tmp/a.txt", "/home/user"), "/tmp/a.txt");
        assert_eq!(
            abs_read_path("src/creds.env", "/home/user/proj"),
            "/home/user/proj/src/creds.env"
        );
        assert_eq!(abs_read_path("src/a.txt", ""), "src/a.txt");
        assert_eq!(abs_read_path("", "/home/user"), "");
        assert_eq!(
            abs_read_path("../bar/x.txt", "/home/user/foo"),
            "/home/user/bar/x.txt"
        );
        assert_eq!(
            abs_read_path("./a//b/x.txt", "/home/user"),
            "/home/user/a/b/x.txt"
        );
        // A backslash is an ordinary filename character on POSIX, so this really
        // is one relative file called `C:\Users\me\x.txt`.
        assert_eq!(
            abs_read_path(r"C:\Users\me\x.txt", "/proj"),
            r"/proj/C:\Users\me\x.txt"
        );
    }

    /// GIVEN the absolute path forms Windows actually uses
    /// WHEN each is resolved against a cwd
    /// THEN it is left alone rather than appended to the cwd, which would make
    /// `is_file()` fail and the file be scanned as prompt text instead.
    #[test]
    #[cfg(windows)]
    fn abs_read_path_recognises_windows_absolute_paths() {
        assert_eq!(
            abs_read_path(r"C:\Users\me\creds.env", r"C:\proj"),
            r"C:\Users\me\creds.env"
        );
        // Forward slashes are separators on Windows too.
        assert_eq!(
            abs_read_path("C:/Users/me/creds.env", r"C:\proj"),
            r"C:\Users\me\creds.env"
        );
        assert_eq!(
            abs_read_path(r"\\host\share\creds.env", r"C:\proj"),
            r"\\host\share\creds.env"
        );
        // Root-relative: `os.path.join` keeps the cwd's drive, and so does this.
        assert_eq!(abs_read_path(r"\creds.env", r"D:\proj"), r"D:\creds.env");
        assert_eq!(
            abs_read_path(r"src\creds.env", r"C:\proj"),
            r"C:\proj\src\creds.env"
        );
        assert_eq!(
            abs_read_path(r"..\bar\x.txt", r"C:\proj\foo"),
            r"C:\proj\bar\x.txt"
        );
    }

    /// GIVEN a relative `@`-mention and an absolute tool `file_path` for one file
    /// WHEN both are parsed
    /// THEN they resolve to the same identifier, so one verdict-cache key covers
    /// both.
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
        let wanted = native("/home/user/proj/src/creds.env");
        assert!(ids.contains(&wanted.as_str()), "{ids:?}");

        let read = claude(json!({
            "cwd": "/home/user/proj",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/home/user/proj/src/creds.env"},
        }))
        .to_string();
        assert_eq!(parse(&read).expect("parses")[0].identifier, wanted);
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
        assert_eq!(Agent::Cursor.event_cwd(&json!({})), "");
    }

    /// GIVEN payloads carrying an event name Kiro shares with another agent, plus
    /// one of that agent's own keys
    /// WHEN the agent is detected
    /// THEN the other agent wins: Kiro is registered last and refuses any payload
    /// carrying a key it never sends.
    #[test]
    fn kiro_never_claims_another_agents_payload() {
        let cases: [(&str, Value, Option<Agent>); 6] = [
            (
                "claude",
                claude(json!({"hook_event_name": "PreToolUse"})),
                Some(Agent::Claude),
            ),
            (
                "cursor",
                json!({"cursor_version": "2.5.25", "hook_event_name": "preToolUse",
                       "tool_name": "Read"}),
                Some(Agent::Cursor),
            ),
            (
                "codex",
                json!({"turn_id": "t1", "hook_event_name": "PreToolUse"}),
                Some(Agent::Codex),
            ),
            (
                "copilot",
                json!({"hook_event_name": "PreToolUse", "session_id": "s",
                       "timestamp": "t", "cwd": "/tmp"}),
                Some(Agent::Copilot),
            ),
            // Junie CLI mirrors Claude Code's field names on purpose, so it
            // reaches Kiro's matcher with a trigger name Kiro also uses.
            (
                "junie cli",
                json!({"hook_event_name": "UserPromptSubmit", "session_id": "s",
                       "cwd": "/p", "project_path": "/p", "prompt": "hello"}),
                None,
            ),
            // Not one of Kiro's trigger spellings, and nothing else matches.
            (
                "unknown trigger",
                json!({"hook_event_name": "beforeShellExecution", "cwd": "/p"}),
                None,
            ),
        ];
        for (label, data, expected) in cases {
            assert_eq!(Agent::detect(&data), expected, "{label}");
        }
    }

    /// GIVEN each Kiro trigger that carries nothing to scan
    /// WHEN it is parsed
    /// THEN Kiro is recognised and the event maps to no type.
    #[test]
    fn kiro_content_free_triggers_are_other_events() {
        for event in [
            "agentSpawn",
            "SessionStart",
            "stop",
            "Stop",
            "PreTaskExec",
            "PostTaskExec",
            "PostFileCreate",
            "PostFileSave",
            "PostFileDelete",
        ] {
            let raw = json!({"hook_event_name": event, "cwd": "/p"}).to_string();
            let payloads = parse(&raw).expect("parses");
            assert_eq!(payloads[0].agent, Agent::Kiro, "{event}");
            assert_eq!(payloads[0].event_type, EventType::Other, "{event}");
        }
    }

    /// GIVEN Kiro's tool names from both surfaces
    /// WHEN each is classified
    /// THEN the readers and the two shells are recognised, and both MCP spellings
    /// (the CLI's `@server/tool` and the IDE's `mcp_server_tool`) are MCP.
    #[test]
    fn kiro_tool_names_map_to_their_tools() {
        let cases = [
            ("fs_read", Tool::Read),
            ("read_file", Tool::Read),
            // Several paths in a shape we have not verified: kept generic so no
            // Read payload is built around a path lookup that finds nothing.
            ("read_files", Tool::Other),
            ("execute_bash", Tool::Bash),
            ("execute_pwsh", Tool::Bash),
            ("@github/create_issue", Tool::Mcp),
            ("mcp_github_create_issue", Tool::Mcp),
            // The writers stay generic so their tool_input is scanned as text.
            ("fs_write", Tool::Other),
            ("str_replace", Tool::Other),
            ("fs_append", Tool::Other),
        ];
        for (tool_name, expected) in cases {
            let data = json!({"tool_name": tool_name});
            assert_eq!(parse_tool(&data), expected, "{tool_name}");
        }
    }

    /// GIVEN a Kiro CLI `fs_write` and a Kiro IDE `str_replace`, the pre-write
    /// blocking path
    /// WHEN each is parsed
    /// THEN the content about to be written is in the scanned text.
    #[test]
    fn kiro_write_tools_scan_the_content_being_written() {
        let raw = json!({
            "hook_event_name": "preToolUse",
            "cwd": "/home/user/proj",
            "tool_name": "fs_write",
            "tool_input": {"command": "create", "path": "/home/user/proj/.env",
                           "file_text": "TOKEN=deadbeef"},
        })
        .to_string();
        let payloads = parse(&raw).expect("parses");
        assert_eq!(payloads[0].agent, Agent::Kiro);
        assert_eq!(payloads[0].event_type, EventType::PreToolUse);
        assert_eq!(payloads[0].tool, Some(Tool::Other));
        assert!(
            payloads[0].content.contains("TOKEN=deadbeef"),
            "{:?}",
            payloads[0].content
        );

        let raw = json!({
            "session_id": "sess_1",
            "hook_event_name": "PreToolUse",
            "cwd": "/home/user/proj",
            "tool_name": "str_replace",
            "tool_input": {"path": "/home/user/proj/a.py", "oldStr": "hi",
                           "newStr": "TOKEN=deadbeef", "replace_all": false},
        })
        .to_string();
        let payloads = parse(&raw).expect("parses");
        assert!(
            payloads[0].content.contains("TOKEN=deadbeef"),
            "{:?}",
            payloads[0].content
        );
    }

    /// GIVEN a Kiro CLI `fs_read`, whose files are named in an `operations` list
    /// WHEN it is parsed
    /// THEN every path in the list becomes its own Read payload, resolved against
    /// `cwd`, and the call's own payload carries nothing to scan.
    #[test]
    fn kiro_fs_read_operations_become_one_payload_per_file() {
        let raw = json!({
            "hook_event_name": "preToolUse",
            "cwd": "/home/user/proj",
            "tool_name": "fs_read",
            "tool_input": {"operations": [
                {"mode": "Line", "path": "/home/user/proj/seed.txt"},
                {"mode": "Line", "path": "creds.env"},
                {"mode": "Directory"},
            ]},
        })
        .to_string();
        let payloads = parse(&raw).expect("parses");
        // The synthesised payloads come first, the call's own payload last.
        let reads: Vec<_> = payloads[..payloads.len() - 1]
            .iter()
            .map(|p| (p.identifier.as_str(), p.event_type, p.read_range))
            .collect();
        assert_eq!(
            reads,
            vec![
                (
                    native("/home/user/proj/seed.txt").as_str(),
                    EventType::PreToolUse,
                    None
                ),
                (
                    native("/home/user/proj/creds.env").as_str(),
                    EventType::PreToolUse,
                    None
                ),
            ]
        );
        // An operations list leaves the call's own payload with no text at all, so
        // `scan_payloads` skips it instead of scanning the empty string. Its
        // identifier is the hash of that empty content, not a path.
        assert!(payloads.last().expect("non-empty").content.is_empty());
    }

    /// GIVEN the PostToolUse of a Kiro CLI `fs_read` of a single file
    /// WHEN it is parsed
    /// THEN the file is the identifier, so the exclusions and the verdict cache
    /// still see a path rather than a hash of the response.
    #[test]
    fn kiro_fs_read_post_tool_use_keeps_the_path() {
        let raw = json!({
            "hook_event_name": "postToolUse",
            "cwd": "/home/user/proj",
            "tool_name": "fs_read",
            "tool_input": {"operations": [{"mode": "Line", "path": "creds.env"}]},
            "tool_response": {"success": true, "result": ["password = hunter2"]},
        })
        .to_string();

        let payloads = parse(&raw).expect("parses");

        assert_eq!(payloads[0].tool, Some(Tool::Read));
        assert_eq!(payloads[0].identifier, native("/home/user/proj/creds.env"));
    }

    /// GIVEN a read of several files at once, which no single path can name
    /// WHEN its PostToolUse is parsed
    /// THEN the response is scanned under a content hash rather than under one
    /// of the files, which would answer for the others too.
    #[test]
    fn kiro_multi_file_read_post_tool_use_falls_back_to_a_hash() {
        let raw = json!({
            "hook_event_name": "postToolUse",
            "cwd": "/home/user/proj",
            "tool_name": "fs_read",
            "tool_input": {"operations": [
                {"mode": "Line", "path": "a.env"},
                {"mode": "Line", "path": "b.env"},
            ]},
            "tool_response": "password = hunter2",
        })
        .to_string();

        let payloads = parse(&raw).expect("parses");

        assert_eq!(payloads[0].identifier, sha256_hex("password = hunter2"));
    }

    /// GIVEN a Kiro prompt and a Kiro read, from either surface
    /// WHEN they are parsed
    /// THEN the prompt is scanned with its @-mentions resolved against `cwd`, and
    /// the read covers the whole file.
    #[test]
    fn kiro_prompt_and_read_use_the_plain_cwd() {
        let raw = json!({
            "hook_event_name": "userPromptSubmit",
            "cwd": "/home/user/proj",
            "prompt": "check @src/creds.env",
        })
        .to_string();
        let payloads = parse(&raw).expect("parses");
        let ids: Vec<_> = payloads.iter().map(|p| p.identifier.as_str()).collect();
        assert!(
            ids.contains(&native("/home/user/proj/src/creds.env").as_str()),
            "{ids:?}"
        );
        assert_eq!(
            payloads.last().expect("non-empty").content,
            "check @src/creds.env"
        );

        let raw = json!({
            "session_id": "sess_1",
            "hook_event_name": "PostToolUse",
            "cwd": "/home/user/proj",
            "tool_name": "read_file",
            "tool_input": {"path": "creds.env"},
            "tool_response": "TOKEN=deadbeef",
        })
        .to_string();
        let payloads = parse(&raw).expect("parses");
        assert_eq!(payloads[0].tool, Some(Tool::Read));
        assert_eq!(payloads[0].identifier, native("/home/user/proj/creds.env"));
        assert_eq!(payloads[0].content, "TOKEN=deadbeef");
        assert_eq!(payloads[0].read_range, None);
    }
}
