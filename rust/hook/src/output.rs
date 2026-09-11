//! The per-agent output contracts. One transcription of `output_result()` per
//! adapter in `ggshield/verticals/ai/agents/`.
//!
//! The schemas disagree about which key blocks, which events can block at
//! all, whether a warning is carried, whether anything is printed when the action
//! is allowed, and what the exit code means. Getting one wrong produces a verdict
//! the agent silently ignores, not an error.

use serde_json::{Map, Value};

use crate::payload::{Agent, EventType, Payload, Tool};

pub struct HookResult<'a> {
    pub block: bool,
    pub message: String,
    // Only read by the macOS desktop notification; the other platforms have
    // no notifier yet, so this is dead there until one is added.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub nbr_secrets: usize,
    pub payload: &'a Payload,
    /// Set when the action is allowed but the user must be warned, typically
    /// because the scan could not run at all.
    pub warning: String,
}

impl<'a> HookResult<'a> {
    pub fn allow(payload: &'a Payload) -> Self {
        HookResult {
            block: false,
            message: String::new(),
            nbr_secrets: 0,
            payload,
            warning: String::new(),
        }
    }

    pub fn allow_with_warning(payload: &'a Payload, warning: String) -> Self {
        HookResult {
            warning,
            ..HookResult::allow(payload)
        }
    }

    pub fn block(payload: &'a Payload, message: String, nbr_secrets: usize) -> Self {
        HookResult {
            block: true,
            message,
            nbr_secrets,
            payload,
            warning: String::new(),
        }
    }
}

/// What an adapter decided to emit: a JSON document on stdout, (Codex's
/// unknown-event branch) a bare message on stderr, or (Vibe's passthrough)
/// nothing at all.
///
/// Serializable because the payload debounce stores one, so a second hook fired
/// for the same event replays the same verdict.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Emission {
    Stdout(Value, i32),
    Stderr(String, i32),
    /// No output whatsoever. Distinct from `Stdout({})`: Vibe's documented
    /// passthrough is an empty stdout, and a bare `{}` is not that.
    Silent(i32),
}

fn obj(pairs: Vec<(&str, Value)>) -> Value {
    let mut map = Map::new();
    for (key, value) in pairs {
        map.insert(key.into(), value);
    }
    Value::Object(map)
}

fn deny_pre_tool_use(message: &str) -> Value {
    obj(vec![(
        "hookSpecificOutput",
        obj(vec![
            ("hookEventName", "PreToolUse".into()),
            ("permissionDecision", "deny".into()),
            ("permissionDecisionReason", message.into()),
        ]),
    )])
}

fn decision_block(message: &str) -> Value {
    obj(vec![
        ("decision", "block".into()),
        ("reason", Value::from(message)),
    ])
}

/// Whether this agent lets the hook replace the tool's output before the model
/// reads it, so a PostToolUse block withholds the secret rather than only
/// warning about it after the fact.
///
/// Drives three things that must agree: the replacement `emission()` sends, the
/// wording `message::from_secrets()` picks, and whether `lib.rs` raises the
/// "already leaked" desktop notification.
pub fn can_redact_tool_output(payload: &Payload) -> bool {
    payload.event_type == EventType::PostToolUse
        && match payload.agent {
            // `updatedToolOutput` must match the tool's own output schema.
            // Claude Code silently ignores a value that does not and shows the
            // original, so only the shapes captured from a real payload count;
            // `claude_updated_tool_output` builds exactly those, and
            // `claude_capability_matches_the_shapes_it_can_build` locks the two
            // together.
            Agent::Claude => matches!(payload.tool, Some(Tool::Bash | Tool::Read)),
            // `decision: "block"` already replaces the tool result, whatever
            // the tool, so Codex needs no extra field in the response. Only the
            // model is protected: Codex also records the raw output in a
            // rollout file of its own, which no hook can reach, so the wording
            // says the output never reached the agent and claims nothing about
            // what is on disk.
            Agent::Codex => true,
            // Vibe is documented to replace a blocked tool result too, and
            // Cursor can for an MCP tool. Neither is established here against a
            // real payload yet, and until it is they keep the leaked wording:
            // telling someone to rotate a secret that never left is a nuisance,
            // telling them not to rotate one that did is a breach.
            Agent::Copilot | Agent::Cursor | Agent::Kiro | Agent::Vibe | Agent::VsCode => false,
        }
}

/// The output Claude Code hands the model in place of the one that held the
/// secret, in that tool's own shape. `None` for a tool whose shape we have not
/// captured, which falls back to warning about a leak that did happen.
fn claude_updated_tool_output(payload: &Payload, message: &str) -> Option<Value> {
    match payload.tool? {
        Tool::Bash => Some(obj(vec![
            ("stdout", message.into()),
            ("stderr", "".into()),
            ("interrupted", false.into()),
            ("isImage", false.into()),
        ])),
        Tool::Read => {
            let lines = message.lines().count().max(1);
            Some(obj(vec![
                ("type", "text".into()),
                (
                    "file",
                    obj(vec![
                        ("filePath", read_file_path(payload).into()),
                        ("content", message.into()),
                        ("numLines", lines.into()),
                        ("startLine", 1.into()),
                        ("totalLines", lines.into()),
                    ]),
                ),
            ]))
        }
        Tool::Mcp | Tool::Other => None,
    }
}

/// The path Claude sent in `tool_input`, so the replacement names the file the
/// agent asked for. Falls back to the payload identifier, which is that path
/// resolved against the event's cwd.
fn read_file_path(payload: &Payload) -> &str {
    payload
        .raw
        .get("tool_input")
        .and_then(|input| input.get("file_path"))
        .and_then(Value::as_str)
        .unwrap_or(&payload.identifier)
}

/// Claude's PostToolUse block. Carries `updatedToolOutput` when the tool's shape
/// is one we can rebuild, which is what keeps the secret out of both the model's
/// context and the session transcript on disk.
fn claude_post_tool_use(result: &HookResult) -> Value {
    let message = result.message.as_str();
    let Some(replacement) = claude_updated_tool_output(result.payload, message) else {
        return decision_block(message);
    };
    let mut value = decision_block(message);
    if let Value::Object(map) = &mut value {
        map.insert(
            "hookSpecificOutput".into(),
            obj(vec![
                ("hookEventName", "PostToolUse".into()),
                ("updatedToolOutput", replacement),
            ]),
        );
    }
    value
}

fn allow_with_optional_warning(warning: &str) -> Value {
    let mut pairs = vec![("continue", true.into())];
    if !warning.is_empty() {
        pairs.push(("systemMessage", warning.into()));
    }
    obj(pairs)
}

pub fn emission(result: &HookResult) -> Emission {
    let message = result.message.as_str();
    let event = result.payload.event_type;
    match result.payload.agent {
        // vibe.py: the event type plays no part here, a plain allow prints
        // nothing, and the keys are `system_message` and `deny`.
        Agent::Vibe => {
            if result.block {
                Emission::Stdout(
                    obj(vec![
                        ("decision", "deny".into()),
                        ("reason", Value::from(message)),
                    ]),
                    0,
                )
            } else if !result.warning.is_empty() {
                Emission::Stdout(
                    obj(vec![("system_message", result.warning.clone().into())]),
                    0,
                )
            } else {
                Emission::Silent(0)
            }
        }

        // claude_code.py
        Agent::Claude => Emission::Stdout(
            if !result.block {
                allow_with_optional_warning(&result.warning)
            } else {
                match event {
                    EventType::PostToolUse => claude_post_tool_use(result),
                    EventType::UserPrompt => decision_block(message),
                    EventType::PreToolUse => deny_pre_tool_use(message),
                    // Should not happen; Claude's "universal" fields.
                    EventType::Other => obj(vec![
                        ("continue", false.into()),
                        ("stopReason", message.into()),
                    ]),
                }
            },
            0,
        ),

        // codex.py. No `additionalContext` (Codex shows the decision reason in
        // the transcript), and the unknown-event branch goes to stderr with exit 2.
        Agent::Codex => {
            if result.block {
                match event {
                    EventType::PreToolUse => Emission::Stdout(deny_pre_tool_use(message), 0),
                    EventType::UserPrompt | EventType::PostToolUse => {
                        Emission::Stdout(decision_block(message), 0)
                    }
                    EventType::Other => Emission::Stderr(message.to_string(), 2),
                }
            } else if !result.warning.is_empty() {
                Emission::Stdout(
                    obj(vec![("systemMessage", result.warning.clone().into())]),
                    0,
                )
            } else {
                Emission::Stdout(Value::Object(Map::new()), 0)
            }
        }

        // cursor.py. It folds the fail-open warning into the same `user_message`
        // field as a block reason, and PostToolUse cannot block at all.
        Agent::Cursor => {
            let message = if result.message.is_empty() {
                result.warning.as_str()
            } else {
                message
            };
            match event {
                EventType::UserPrompt => Emission::Stdout(
                    obj(vec![
                        ("continue", (!result.block).into()),
                        ("user_message", message.into()),
                    ]),
                    0,
                ),
                EventType::PreToolUse => Emission::Stdout(
                    obj(vec![
                        (
                            "permission",
                            if result.block { "deny" } else { "allow" }.into(),
                        ),
                        ("user_message", message.into()),
                        ("agent_message", message.into()),
                    ]),
                    0,
                ),
                EventType::PostToolUse => Emission::Stdout(Value::Object(Map::new()), 0),
                EventType::Other => {
                    Emission::Stdout(Value::Object(Map::new()), if result.block { 2 } else { 0 })
                }
            }
        }

        // vscode.py, and copilot.py which subclasses it. Copilot overrides
        // exactly one case: a blocked prompt, because it ignores the inherited
        // `{"continue": false}` but honours `{"decision": "block"}`.
        Agent::VsCode | Agent::Copilot => Emission::Stdout(
            if !result.block {
                allow_with_optional_warning(&result.warning)
            } else {
                match event {
                    EventType::PreToolUse => deny_pre_tool_use(message),
                    EventType::PostToolUse => decision_block(message),
                    EventType::UserPrompt if result.payload.agent == Agent::Copilot => {
                        decision_block(message)
                    }
                    _ => obj(vec![
                        ("continue", false.into()),
                        ("stopReason", message.into()),
                    ]),
                }
            },
            0,
        ),

        // Kiro, which this hook serves alone: its Python adapter declines every
        // payload, so there is nothing to mirror here. There is no JSON verdict
        // protocol on either surface: Kiro reads exit 2 as "blocked" and
        // forwards the stderr text to the model.
        Agent::Kiro => {
            if result.block {
                match event {
                    // Constraint: the Kiro IDE does not honour a non-zero exit on
                    // its prompt-submit trigger, so the prompt reaches the model
                    // anyway and the verdict is advisory there. It blocks on the CLI.
                    EventType::UserPrompt | EventType::PreToolUse => {
                        Emission::Stderr(message.to_string(), 2)
                    }
                    // Nothing to block after the fact; lib.rs raises the desktop
                    // notification for PostToolUse.
                    EventType::PostToolUse | EventType::Other => Emission::Silent(0),
                }
            } else if !result.warning.is_empty() {
                // A fail-open warning is text for the model, not a block, so the
                // exit code stays 0.
                Emission::Stderr(result.warning.clone(), 0)
            } else {
                Emission::Silent(0)
            }
        }
    }
}

/// Prints the verdict and returns the process exit code.
pub fn output_result(result: &HookResult) -> i32 {
    emit(emission(result))
}

/// Prints one emission, whether it was just decided or replayed from the
/// debounce, and returns the process exit code.
pub fn emit(emission: Emission) -> i32 {
    match emission {
        Emission::Stdout(value, code) => {
            println!("{value}");
            code
        }
        Emission::Stderr(message, code) => {
            eprintln!("{message}");
            code
        }
        Emission::Silent(code) => code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::Tool;

    fn payload(agent: Agent, event_type: EventType) -> Payload {
        payload_with_tool(agent, event_type, Some(Tool::Bash))
    }

    fn payload_with_tool(agent: Agent, event_type: EventType, tool: Option<Tool>) -> Payload {
        Payload {
            event_type,
            tool,
            content: String::new(),
            identifier: "id".into(),
            agent,
            cwd: String::new(),
            raw: Value::Object(Default::default()),
            read_range: None,
        }
    }

    /// stdout bytes for a result, or `None` when the adapter writes to stderr or
    /// emits nothing at all.
    fn emitted(result: &HookResult) -> Option<String> {
        match emission(result) {
            Emission::Stdout(value, _) => Some(value.to_string()),
            Emission::Stderr(..) | Emission::Silent(..) => None,
        }
    }

    fn blocked(agent: Agent, event: EventType) -> Option<String> {
        let p = payload(agent, event);
        emitted(&HookResult::block(&p, "nope".into(), 1))
    }

    fn blocked_tool(agent: Agent, event: EventType, tool: Option<Tool>) -> Option<String> {
        let p = payload_with_tool(agent, event, tool);
        emitted(&HookResult::block(&p, "nope".into(), 1))
    }

    fn allowed(agent: Agent, event: EventType) -> Option<String> {
        let p = payload(agent, event);
        emitted(&HookResult::allow(&p))
    }

    fn warned(agent: Agent, event: EventType) -> Option<String> {
        let p = payload(agent, event);
        emitted(&HookResult::allow_with_warning(&p, "could not scan".into()))
    }

    const DENY: &str = r#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"nope"}}"#;

    /// GIVEN an allow, a fail-open warning and a block on each Vibe event
    /// WHEN they are emitted
    /// THEN an allow prints nothing at all, a block denies in snake_case, and the
    /// verdict is the same whatever the event — Vibe's schema ignores it.
    #[test]
    fn vibe_contract() {
        for event in [
            EventType::UserPrompt,
            EventType::PreToolUse,
            EventType::PostToolUse,
            EventType::Other,
        ] {
            let p = payload(Agent::Vibe, event);
            assert!(
                matches!(emission(&HookResult::allow(&p)), Emission::Silent(0)),
                "vibe must emit nothing when allowing {event:?}"
            );
            assert_eq!(
                blocked(Agent::Vibe, event).as_deref(),
                Some(r#"{"decision":"deny","reason":"nope"}"#),
                "{event:?}"
            );
            assert_eq!(
                warned(Agent::Vibe, event).as_deref(),
                Some(r#"{"system_message":"could not scan"}"#),
                "{event:?}"
            );
        }
    }

    /// GIVEN an allow, a fail-open warning and a block on each Claude event
    /// WHEN they are emitted
    /// THEN the JSON is Claude's hook contract, and Claude is the only adapter that
    /// repeats the reason as `additionalContext`.
    #[test]
    fn claude_contract() {
        assert_eq!(
            allowed(Agent::Claude, EventType::PreToolUse).as_deref(),
            Some(r#"{"continue":true}"#)
        );
        assert_eq!(
            warned(Agent::Claude, EventType::PreToolUse).as_deref(),
            Some(r#"{"continue":true,"systemMessage":"could not scan"}"#)
        );
        assert_eq!(
            blocked(Agent::Claude, EventType::PreToolUse).as_deref(),
            Some(DENY)
        );
        // A Bash output is replaced, so the model reads the block message
        // instead of the output that held the secret.
        assert_eq!(
            blocked(Agent::Claude, EventType::PostToolUse).as_deref(),
            Some(
                r#"{"decision":"block","reason":"nope","hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":{"stdout":"nope","stderr":"","interrupted":false,"isImage":false}}}"#
            )
        );
        // A blocked prompt carries no additionalContext: Claude Code reads that
        // field only under hookSpecificOutput, and a blocked prompt is erased
        // without a model turn, so nothing could be delivered anyway.
        assert_eq!(
            blocked(Agent::Claude, EventType::UserPrompt).as_deref(),
            Some(r#"{"decision":"block","reason":"nope"}"#)
        );
        assert_eq!(
            blocked(Agent::Claude, EventType::Other).as_deref(),
            Some(r#"{"continue":false,"stopReason":"nope"}"#)
        );
    }

    /// GIVEN an allow, a warning and a block on each Codex event
    /// WHEN they are emitted
    /// THEN allowing is a bare `{}`, a block carries no `additionalContext`, and an
    /// unknown event goes to stderr with exit 2.
    #[test]
    fn codex_contract() {
        // Allowing emits a bare {}, not {"continue": true}.
        assert_eq!(
            allowed(Agent::Codex, EventType::PreToolUse).as_deref(),
            Some("{}")
        );
        assert_eq!(
            warned(Agent::Codex, EventType::PreToolUse).as_deref(),
            Some(r#"{"systemMessage":"could not scan"}"#)
        );
        assert_eq!(
            blocked(Agent::Codex, EventType::PreToolUse).as_deref(),
            Some(DENY)
        );
        // No additionalContext: Codex would show the reason twice.
        assert_eq!(
            blocked(Agent::Codex, EventType::PostToolUse).as_deref(),
            Some(r#"{"decision":"block","reason":"nope"}"#)
        );
        // Unknown event: stderr and exit 2, nothing on stdout.
        let p = payload(Agent::Codex, EventType::Other);
        match emission(&HookResult::block(&p, "nope".into(), 1)) {
            Emission::Stderr(message, code) => {
                assert_eq!(message, "nope");
                assert_eq!(code, 2);
            }
            _ => panic!("Codex must not emit JSON for an unknown event"),
        }
    }

    /// GIVEN an allow, a warning and a block on each Cursor event
    /// WHEN they are emitted
    /// THEN prompts use `continue`/`user_message`, tool calls use `permission`,
    /// PostToolUse is always a bare `{}`, and the warning rides in `user_message`.
    #[test]
    fn cursor_contract() {
        assert_eq!(
            allowed(Agent::Cursor, EventType::UserPrompt).as_deref(),
            Some(r#"{"continue":true,"user_message":""}"#)
        );
        assert_eq!(
            blocked(Agent::Cursor, EventType::UserPrompt).as_deref(),
            Some(r#"{"continue":false,"user_message":"nope"}"#)
        );
        assert_eq!(
            allowed(Agent::Cursor, EventType::PreToolUse).as_deref(),
            Some(r#"{"permission":"allow","user_message":"","agent_message":""}"#)
        );
        assert_eq!(
            blocked(Agent::Cursor, EventType::PreToolUse).as_deref(),
            Some(r#"{"permission":"deny","user_message":"nope","agent_message":"nope"}"#)
        );
        // Cursor cannot block after the fact: PostToolUse is always a bare {}.
        assert_eq!(
            blocked(Agent::Cursor, EventType::PostToolUse).as_deref(),
            Some("{}")
        );
        // The fail-open warning rides in user_message, not systemMessage.
        assert_eq!(
            warned(Agent::Cursor, EventType::UserPrompt).as_deref(),
            Some(r#"{"continue":true,"user_message":"could not scan"}"#)
        );
    }

    /// GIVEN an allow and a block on each VS Code event
    /// WHEN they are emitted
    /// THEN tool calls use the deny/block shapes, and a blocked prompt stops the run
    /// with `stopReason` rather than cancelling the prompt.
    #[test]
    fn vscode_contract() {
        assert_eq!(
            allowed(Agent::VsCode, EventType::PreToolUse).as_deref(),
            Some(r#"{"continue":true}"#)
        );
        assert_eq!(
            blocked(Agent::VsCode, EventType::PreToolUse).as_deref(),
            Some(DENY)
        );
        assert_eq!(
            blocked(Agent::VsCode, EventType::PostToolUse).as_deref(),
            Some(r#"{"decision":"block","reason":"nope"}"#)
        );
        // A blocked prompt stops the run rather than cancelling the prompt.
        assert_eq!(
            blocked(Agent::VsCode, EventType::UserPrompt).as_deref(),
            Some(r#"{"continue":false,"stopReason":"nope"}"#)
        );
    }

    /// GIVEN the same results emitted for Copilot and for VS Code
    /// WHEN every event is compared
    /// THEN they agree everywhere except a blocked prompt.
    #[test]
    fn copilot_differs_from_vscode_only_on_a_blocked_prompt() {
        assert_eq!(
            blocked(Agent::Copilot, EventType::UserPrompt).as_deref(),
            Some(r#"{"decision":"block","reason":"nope"}"#)
        );
        for event in [
            EventType::PreToolUse,
            EventType::PostToolUse,
            EventType::Other,
        ] {
            assert_eq!(
                blocked(Agent::Copilot, event),
                blocked(Agent::VsCode, event),
                "copilot must inherit vscode for {event:?}"
            );
            assert_eq!(
                allowed(Agent::Copilot, event),
                allowed(Agent::VsCode, event)
            );
        }
    }

    /// GIVEN a secret in a file Claude just read
    /// WHEN the block is emitted
    /// THEN the replacement is the Read tool's own output shape, naming the file
    /// the agent asked for.
    #[test]
    fn a_replaced_read_uses_the_read_output_shape() {
        let mut p = payload_with_tool(Agent::Claude, EventType::PostToolUse, Some(Tool::Read));
        p.raw = serde_json::json!({"tool_input": {"file_path": "/tmp/creds.env"}});
        let emitted = emitted(&HookResult::block(&p, "line one\nline two".into(), 1))
            .expect("claude emits json");
        let value: Value = serde_json::from_str(&emitted).expect("valid json");
        let file = &value["hookSpecificOutput"]["updatedToolOutput"]["file"];
        assert_eq!(
            value["hookSpecificOutput"]["updatedToolOutput"]["type"],
            "text"
        );
        assert_eq!(file["filePath"], "/tmp/creds.env");
        assert_eq!(file["content"], "line one\nline two");
        assert_eq!(file["numLines"], 2);
        assert_eq!(file["startLine"], 1);
        assert_eq!(file["totalLines"], 2);
    }

    /// GIVEN a Claude tool whose output shape we cannot rebuild
    /// WHEN the block is emitted
    /// THEN no replacement is sent, because Claude Code silently ignores a value
    /// that does not match the schema and would show the original output.
    #[test]
    fn an_unknown_claude_tool_gets_no_replacement() {
        for tool in [Some(Tool::Mcp), Some(Tool::Other), None] {
            assert_eq!(
                blocked_tool(Agent::Claude, EventType::PostToolUse, tool).as_deref(),
                Some(r#"{"decision":"block","reason":"nope"}"#),
                "{tool:?}"
            );
        }
    }

    /// GIVEN every tool
    /// WHEN Claude's capability flag and the shape builder are compared
    /// THEN they agree. They are two matches that must not drift: claiming a
    /// redaction we do not send would tell the user a leaked secret was safe.
    #[test]
    fn claude_capability_matches_the_shapes_it_can_build() {
        for tool in [
            Some(Tool::Bash),
            Some(Tool::Read),
            Some(Tool::Mcp),
            Some(Tool::Other),
            None,
        ] {
            let p = payload_with_tool(Agent::Claude, EventType::PostToolUse, tool);
            assert_eq!(
                can_redact_tool_output(&p),
                claude_updated_tool_output(&p, "nope").is_some(),
                "{tool:?}"
            );
        }
    }

    /// GIVEN each agent and each event
    /// WHEN the redaction capability is read
    /// THEN only PostToolUse can redact, only on the agents proven to replace an
    /// output, and Codex does so whatever the tool.
    #[test]
    fn only_proven_agents_report_that_they_can_withhold_an_output() {
        for event in [
            EventType::UserPrompt,
            EventType::PreToolUse,
            EventType::Other,
        ] {
            for agent in crate::payload::AGENTS {
                assert!(
                    !can_redact_tool_output(&payload(agent, event)),
                    "{agent:?}/{event:?} is not a tool output"
                );
            }
        }
        // Codex replaces the tool result whatever the tool, so it needs no
        // shape of its own and every tool redacts.
        for tool in [Some(Tool::Bash), Some(Tool::Read), Some(Tool::Mcp), None] {
            assert!(can_redact_tool_output(&payload_with_tool(
                Agent::Codex,
                EventType::PostToolUse,
                tool
            )));
        }
        for agent in [
            Agent::Copilot,
            Agent::Cursor,
            Agent::Kiro,
            Agent::Vibe,
            Agent::VsCode,
        ] {
            assert!(
                !can_redact_tool_output(&payload(agent, EventType::PostToolUse)),
                "{agent:?} has no verified way to replace an output"
            );
        }
    }

    /// `(stderr text, exit code)`, or `None` when the adapter emits nothing.
    fn stderr_of(result: &HookResult) -> Option<(String, i32)> {
        match emission(result) {
            Emission::Stderr(message, code) => Some((message, code)),
            Emission::Silent(..) => None,
            Emission::Stdout(value, _) => panic!("unexpected stdout: {value}"),
        }
    }

    /// GIVEN an allow, a fail-open warning and a block on each Kiro event
    /// WHEN they are emitted
    /// THEN nothing ever reaches stdout: a block on a prompt or a tool call is
    /// stderr with exit 2, a warning is stderr with exit 0, and everything else is
    /// silent.
    #[test]
    fn kiro_contract() {
        for event in [
            EventType::UserPrompt,
            EventType::PreToolUse,
            EventType::PostToolUse,
            EventType::Other,
        ] {
            let p = payload(Agent::Kiro, event);
            assert_eq!(stderr_of(&HookResult::allow(&p)), None, "{event:?}");
            assert_eq!(
                stderr_of(&HookResult::allow_with_warning(&p, "could not scan".into())),
                Some(("could not scan".to_string(), 0)),
                "{event:?}"
            );
        }

        // Only the two events Kiro can still act on block, and exit 2 is what it
        // reads as "blocked".
        for event in [EventType::UserPrompt, EventType::PreToolUse] {
            let p = payload(Agent::Kiro, event);
            assert_eq!(
                stderr_of(&HookResult::block(&p, "nope".into(), 1)),
                Some(("nope".to_string(), 2)),
                "{event:?}"
            );
        }
        // Too late to block: lib.rs notifies instead.
        for event in [EventType::PostToolUse, EventType::Other] {
            let p = payload(Agent::Kiro, event);
            assert_eq!(
                stderr_of(&HookResult::block(&p, "nope".into(), 1)),
                None,
                "{event:?}"
            );
        }
    }
}
