//! The per-agent output contracts. One transcription of `output_result()` per
//! adapter in `ggshield/verticals/ai/agents/`.
//!
//! The six schemas disagree about which key blocks, which events can block at
//! all, whether a warning is carried, whether anything is printed when the action
//! is allowed, and what the exit code means. Getting one wrong produces a verdict
//! the agent silently ignores, not an error.

use serde_json::{Map, Value};

use crate::payload::{Agent, EventType, Payload};

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

fn decision_block(message: &str, with_context: bool) -> Value {
    let mut pairs = vec![
        ("decision", "block".into()),
        ("reason", Value::from(message)),
    ];
    if with_context {
        pairs.push(("additionalContext", message.into()));
    }
    obj(pairs)
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
                    EventType::UserPrompt | EventType::PostToolUse => decision_block(message, true),
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
                        Emission::Stdout(decision_block(message, false), 0)
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
                    EventType::PostToolUse => decision_block(message, false),
                    EventType::UserPrompt if result.payload.agent == Agent::Copilot => {
                        decision_block(message, false)
                    }
                    _ => obj(vec![
                        ("continue", false.into()),
                        ("stopReason", message.into()),
                    ]),
                }
            },
            0,
        ),
    }
}

/// Prints the verdict and returns the process exit code.
pub fn output_result(result: &HookResult) -> i32 {
    match emission(result) {
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
        Payload {
            event_type,
            tool: Some(Tool::Bash),
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
        // Claude is the only adapter that also sets additionalContext.
        assert_eq!(
            blocked(Agent::Claude, EventType::PostToolUse).as_deref(),
            Some(r#"{"decision":"block","reason":"nope","additionalContext":"nope"}"#)
        );
        assert_eq!(
            blocked(Agent::Claude, EventType::UserPrompt).as_deref(),
            Some(r#"{"decision":"block","reason":"nope","additionalContext":"nope"}"#)
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
}
