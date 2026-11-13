//! The block message shown to the user. Mirrors the templates and
//! `_message_from_secrets()` in `hooks.py`.
//!
//! Every line of prose lives in `templates/`, and a template file *is* the text it
//! renders: no trailing newline, and the two spaces some lines end with are
//! markdown hard breaks (see [`HARD_BREAK`]) that an editor must not strip.

use crate::api::{Secret, Validity};
use crate::payload::{EventType, Payload, Tool};

const MAXIMUM_CENSOR_LENGTH: usize = 60;

const USER_PROMPT_TEMPLATE: &str = include_str!("templates/user_prompt.in");
const PRE_BASH_TEMPLATE: &str = include_str!("templates/pre_bash.in");
const PRE_READ_TEMPLATE: &str = include_str!("templates/pre_read.in");
const PRE_OTHER_TEMPLATE: &str = include_str!("templates/pre_other.in");
const POST_BASH_TEMPLATE: &str = include_str!("templates/post_bash.in");
const POST_READ_TEMPLATE: &str = include_str!("templates/post_read.in");
const POST_OTHER_TEMPLATE: &str = include_str!("templates/post_other.in");
// Used when the agent lets us replace the output, so the secret never reached
// the model and the leaked wording would send the user to rotate for nothing.
const POST_BASH_REDACTED_TEMPLATE: &str = include_str!("templates/post_bash_redacted.in");
const POST_READ_REDACTED_TEMPLATE: &str = include_str!("templates/post_read_redacted.in");
const POST_OTHER_REDACTED_TEMPLATE: &str = include_str!("templates/post_other_redacted.in");
const SECRET_LINE_TEMPLATE: &str = include_str!("templates/secret_line.in");
const INCIDENT_URL_LINE_TEMPLATE: &str = include_str!("templates/incident_url_line.in");
const REMEDIATION_STEPS_TEMPLATE: &str = include_str!("templates/remediation_steps.in");
const REMEDIATION_STEPS_WITH_INCIDENT_TEMPLATE: &str =
    include_str!("templates/remediation_steps_with_incident.in");
const AGENT_INSTRUCTIONS_TEMPLATE: &str = include_str!("templates/agent_instructions.in");
const FALSE_POSITIVE_TEMPLATE: &str = include_str!("templates/false_positive.in");
const IGNORE_COMMAND_TEMPLATE: &str = include_str!("templates/ignore_command.in");
// A pointer, not the command: a banner truncates long text and cannot be
// copied from, and the command carries a 64-character sha.
const FALSE_POSITIVE_NOTIFICATION_TEMPLATE: &str =
    include_str!("templates/false_positive_notification.in");
// Safe inside double quotes in POSIX shells, PowerShell and cmd.
const IGNORE_NAME_PUNCTUATION: &str = " ._-/:@+,=()[]";

/// Agents render the message as markdown, where a single newline collapses into a
/// space; two trailing spaces keep the break. The lines of a list are joined with
/// it, never after the last one.
const HARD_BREAK: &str = "  \n";

/// `pluralize()`. Note that 0 is plural in English.
pub fn pluralize(name: &str, nb: usize, plural: Option<&str>) -> String {
    if nb == 1 {
        name.to_string()
    } else {
        plural
            .map(str::to_string)
            .unwrap_or_else(|| format!("{name}s"))
    }
}

/// `censor_string()`: reveal the first and last sixth of the match, hide the
/// middle. `REGEX_MATCH_HIDE` is `[^+\-\s]`, so `+`, `-` and whitespace survive
/// censoring. Indices are character indices, as in Python.
pub fn censor_string(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    if len <= 2 {
        return "*".repeat(len);
    }
    if len == 3 {
        return format!("**{}", chars[2]);
    }
    let censor_start = len.div_ceil(6).min(MAXIMUM_CENSOR_LENGTH);
    let censor_end = len - censor_start;

    let mut out = String::with_capacity(text.len());
    for (i, c) in chars.iter().enumerate() {
        if i >= censor_start && i < censor_end && !(*c == '+' || *c == '-' || c.is_whitespace()) {
            out.push('*');
        } else {
            out.push(*c);
        }
    }
    out
}

/// One ignore command per distinct ignore sha, in the order the secrets are
/// reported. See `_false_positive_block()`.
///
/// The command names its secret by sha, so it reads no scan cache. The hint
/// sends it to the repository root: see `_false_positive_block()`.
fn ignore_commands(secrets: &[&Secret], payload: &Payload) -> String {
    let mut seen: Vec<String> = Vec::new();
    let mut commands: Vec<String> = Vec::new();
    for secret in secrets {
        let sha = crate::api::ignore_sha(&secret.matches);
        if !seen.contains(&sha) {
            commands.push(render(
                IGNORE_COMMAND_TEMPLATE,
                &[("sha", sha.clone()), ("name", ignore_name(secret, payload))],
            ));
            seen.push(sha);
        }
    }
    commands.join("\n")
}

/// `_ignore_name()`: the detector, plus the file for a read. Any other character
/// becomes `_` (`\\` becomes `/`), so a file name cannot close the quotes or
/// expand in the shell the command is pasted into.
fn ignore_name(secret: &Secret, payload: &Payload) -> String {
    let mut name = secret.detector_display_name.clone();
    if payload.tool == Some(Tool::Read) {
        name.push_str(" - ");
        name.push_str(&payload.identifier);
    }
    name.chars()
        .map(|c| match c {
            c if c.is_ascii_alphanumeric() || IGNORE_NAME_PUNCTUATION.contains(c) => c,
            '\\' => '/',
            _ => '_',
        })
        .collect()
}

/// One bullet per secret, plus its incident URL when we know one. The censoring
/// asterisks become bullets, which markdown would otherwise read as emphasis.
fn secret_lines(secrets: &[Secret]) -> String {
    let mut lines: Vec<String> = Vec::new();
    for secret in secrets {
        let label = secret
            .validity
            .as_ref()
            .unwrap_or(&Validity::Unknown)
            .label();
        let validity = if label == "valid" {
            format!("**{label}**")
        } else {
            label
        };
        let matches = secret
            .matches
            .iter()
            .map(|m| censor_string(&m.value).replace('*', "•"))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(render(
            SECRET_LINE_TEMPLATE,
            &[
                ("detector", secret.detector_display_name.clone()),
                ("validity", validity),
                ("matches", matches),
            ],
        ));
        if secret.known_secret
            && let Some(url) = &secret.incident_url
        {
            lines.push(render(
                INCIDENT_URL_LINE_TEMPLATE,
                &[("incident_url", url.clone())],
            ));
        }
    }
    lines.join(HARD_BREAK)
}

/// `_message_from_secrets(escape_markdown=True)`. Dispatches event-first then
/// tool: what the message says depends first on *when* the secret was caught.
///
/// Called only with at least one secret, which is what lets the templates
/// hard-break into the secret list.
pub fn from_secrets(secrets: &[Secret], payload: &Payload) -> String {
    // Whether the output was withheld from the model decides the whole second
    // half of the message: what happened, and whether there is anything to
    // revoke. See `output::can_redact_tool_output`.
    let withheld = crate::output::can_redact_tool_output(payload);
    let template = match (payload.event_type, payload.tool) {
        // A UserPrompt event also carries a Tool::Read payload per file mentioned
        // in the prompt: the secret is in that file, not in the prompt, so the
        // prompt wording would name the wrong content.
        (EventType::UserPrompt, Some(Tool::Read)) => PRE_READ_TEMPLATE,
        (EventType::UserPrompt, _) => USER_PROMPT_TEMPLATE,
        (EventType::PostToolUse, Some(Tool::Bash)) if withheld => POST_BASH_REDACTED_TEMPLATE,
        (EventType::PostToolUse, Some(Tool::Read)) if withheld => POST_READ_REDACTED_TEMPLATE,
        (EventType::PostToolUse, _) if withheld => POST_OTHER_REDACTED_TEMPLATE,
        (EventType::PostToolUse, Some(Tool::Bash)) => POST_BASH_TEMPLATE,
        (EventType::PostToolUse, Some(Tool::Read)) => POST_READ_TEMPLATE,
        (EventType::PostToolUse, _) => POST_OTHER_TEMPLATE,
        // PreToolUse, and EventType::Other, share the "not leaked yet" wording.
        (_, Some(Tool::Bash)) => PRE_BASH_TEMPLATE,
        (_, Some(Tool::Read)) => PRE_READ_TEMPLATE,
        (_, _) => PRE_OTHER_TEMPLATE,
    };

    let count = secrets.len();
    let nb_incidents = secrets
        .iter()
        .filter(|s| s.known_secret && s.incident_url.is_some())
        .count();
    // The words first: the blocks below render from the same fields.
    let mut fields = vec![
        ("count", count.to_string()),
        ("secrets", pluralize("secret", count, None)),
        ("were", pluralize("was", count, Some("were"))),
        ("them", pluralize("it", count, Some("them"))),
        ("new_ones", pluralize("a new one", count, Some("new ones"))),
        (
            "their_providers",
            pluralize("its provider", count, Some("their providers")),
        ),
        ("incidents", pluralize("incident", nb_incidents, None)),
        ("identifier", payload.identifier.clone()),
        ("secret_lines", secret_lines(secrets)),
    ];
    let steps = if nb_incidents > 0 {
        REMEDIATION_STEPS_WITH_INCIDENT_TEMPLATE
    } else {
        REMEDIATION_STEPS_TEMPLATE
    };
    fields.push(("remediation_steps", render(steps, &fields)));
    fields.push((
        "agent_instructions",
        render(AGENT_INSTRUCTIONS_TEMPLATE, &fields),
    ));
    render(template, &fields)
}

/// The false-positive hint for the agent's user-only field, or an empty string
/// when the agent has no such field or every secret is valid.
pub fn user_message(secrets: &[Secret], payload: &Payload) -> String {
    if !crate::output::has_user_only_channel(payload) {
        return String::new();
    }
    false_positive_hint(secrets, payload, FALSE_POSITIVE_TEMPLATE).unwrap_or_default()
}

/// The one-line false-positive hint for the desktop notification, the user's
/// only channel on an agent without a user-only field. Empty when the agent has
/// one, or when every secret is valid.
pub fn notification_hint(secrets: &[Secret], payload: &Payload) -> String {
    if crate::output::has_user_only_channel(payload) {
        return String::new();
    }
    false_positive_hint(secrets, payload, FALSE_POSITIVE_NOTIFICATION_TEMPLATE).unwrap_or_default()
}

fn is_valid(secret: &Secret) -> bool {
    matches!(secret.validity, Some(Validity::Valid))
}

/// A false-positive hint about the secrets not checked as valid, or `None` when
/// there are none: a working secret is never one to ignore.
fn false_positive_hint(secrets: &[Secret], payload: &Payload, template: &str) -> Option<String> {
    let candidates: Vec<&Secret> = secrets.iter().filter(|s| !is_valid(s)).collect();
    if candidates.is_empty() {
        return None;
    }
    let count = candidates.len();
    let this_is = if candidates.len() == secrets.len() {
        pluralize(
            "this is a false positive",
            count,
            Some("these are false positives"),
        )
    } else {
        pluralize(
            "the secret not marked valid is a false positive",
            count,
            Some("the secrets not marked valid are false positives"),
        )
    };
    Some(render(
        template,
        &[
            ("this_is", this_is),
            ("commands", ignore_commands(&candidates, payload)),
        ],
    ))
}

/// One pass, like `str.format`. Chained `replace` calls would re-scan inserted
/// text, letting a server-supplied detector name containing `{were}` reach into
/// the template.
fn render(template: &str, fields: &[(&str, String)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('}') {
            Some(end) => {
                let name = &after[..end];
                match fields.iter().find(|(key, _)| *key == name) {
                    Some((_, value)) => out.push_str(value),
                    // Not a placeholder we know: emit it verbatim.
                    None => {
                        out.push('{');
                        out.push_str(name);
                        out.push('}');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Match;
    use serde_json::Value;

    fn secret(detector: &str, validity: &str, matches: &[&str]) -> Secret {
        Secret {
            detector_display_name: detector.into(),
            validity: serde_json::from_value(Value::String(validity.into())).expect("validity"),
            known_secret: false,
            incident_url: None,
            matches: matches
                .iter()
                .map(|m| Match {
                    value: (*m).into(),
                    match_type: "apikey".into(),
                })
                .collect(),
        }
    }

    fn payload(event_type: EventType, tool: Option<Tool>, identifier: &str) -> Payload {
        payload_for(crate::payload::Agent::Claude, event_type, tool, identifier)
    }

    /// The agent decides whether a PostToolUse output was withheld from the
    /// model, and so which half of the message the templates render.
    fn payload_for(
        agent: crate::payload::Agent,
        event_type: EventType,
        tool: Option<Tool>,
        identifier: &str,
    ) -> Payload {
        Payload {
            event_type,
            tool,
            content: String::new(),
            identifier: identifier.into(),
            agent,
            cwd: String::new(),
            raw: Value::Object(Default::default()),
            read_range: None,
        }
    }

    /// GIVEN a match value
    /// WHEN it is censored
    /// THEN a sixth is revealed at each end and `+`, `-` and whitespace survive.
    #[test]
    fn censor_matches_python_behaviour() {
        assert_eq!(censor_string(""), "");
        assert_eq!(censor_string("ab"), "**");
        assert_eq!(censor_string("abc"), "**c");
        // ceil(12/6) == 2 revealed at each end.
        assert_eq!(censor_string("abcdefghijkl"), "ab********kl");
        // '+', '-' and whitespace survive the censoring regex.
        assert_eq!(censor_string("aa++--  zz"), "aa++--  zz");
    }

    /// GIVEN a count
    /// WHEN a word is pluralized
    /// THEN only 1 is singular; 0 is plural, as in English.
    #[test]
    fn pluralization_treats_zero_as_plural() {
        assert_eq!(pluralize("secret", 1, None), "secret");
        assert_eq!(pluralize("secret", 0, None), "secrets");
        assert_eq!(pluralize("was", 2, Some("were")), "were");
    }

    /// GIVEN the templates, which `include_str!` embeds byte for byte
    /// WHEN the checked-out files are read
    /// THEN none holds a carriage return, so a CRLF checkout cannot put CRLF in the
    /// messages we print. `.gitattributes` pins them to LF; this catches a template
    /// that escapes that rule.
    #[test]
    fn templates_are_free_of_carriage_returns() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/templates");
        for entry in std::fs::read_dir(dir).expect("the templates directory") {
            let path = entry.expect("a directory entry").path();
            let body = std::fs::read_to_string(&path).expect("a readable template");
            assert!(!body.contains('\r'), "{} has CRLF endings", path.display());
        }
    }

    /// GIVEN a valid secret found in a command about to run
    /// WHEN the block message is built
    /// THEN it is the PreToolUse/Bash wording, with the match censored into bullets.
    #[test]
    fn pre_tool_bash_message_is_the_python_text() {
        let secrets = vec![secret(
            "Generic High Entropy Secret",
            "valid",
            &["byIvSsomethingTXHU"],
        )];
        let p = payload(EventType::PreToolUse, Some(Tool::Bash), "echo x");
        let msg = from_secrets(&secrets, &p);
        assert!(
            msg.starts_with("**🚨 Detected 1 secret in the command 🚨**  \n"),
            "{msg}"
        );
        assert!(msg.contains("  - Generic High Entropy Secret (**valid**): byI"));
        // The censoring asterisks are rendered as bullets.
        assert!(!msg.contains("): byI*"), "{msg}");
        assert!(msg.contains("The command was not executed and the secret was not leaked."));
        assert!(!msg.contains("secret ignore"), "{msg}");
        assert!(
            msg.ends_with("do not suggest disabling or uninstalling the GitGuardian hook."),
            "{msg}"
        );
    }

    /// GIVEN two secrets that share one ignore sha
    /// WHEN the ignore commands are built
    /// THEN the command appears once: running it twice ignores nothing more.
    #[test]
    fn the_ignore_commands_are_deduplicated() {
        let one = secret("AWS Keys", "valid", &["aaa"]);
        let same = secret("AWS Keys", "valid", &["aaa"]);
        let other = secret("Generic Password", "valid", &["bbb"]);
        let p = payload(EventType::PreToolUse, Some(Tool::Bash), "echo x");
        let rendered = ignore_commands(&[&one, &same, &other], &p);

        assert_eq!(rendered.lines().count(), 2, "{rendered}");
        for line in rendered.lines() {
            assert!(line.starts_with("    ggshield secret ignore "), "{line}");
        }
    }

    /// GIVEN a secret in a read file, and one in a command
    /// WHEN the ignore name is built
    /// THEN a read names the detector and the file, anything else the detector
    /// alone, and no character that a shell expands or that closes the quotes
    /// survives.
    #[test]
    fn the_ignore_name_is_safe_to_paste_in_a_shell() {
        let s = secret("Generic Password", "unknown", &["hunter2hunter2"]);
        let read = |path: &str| payload(EventType::PreToolUse, Some(Tool::Read), path);
        assert_eq!(
            ignore_name(&s, &read("/repo/config/.env")),
            "Generic Password - /repo/config/.env"
        );
        assert_eq!(
            ignore_name(&s, &read(r"C:\repo\.env")),
            "Generic Password - C:/repo/.env"
        );
        assert_eq!(
            ignore_name(&s, &read("/repo/a\"$(id)`id`%PATH%!x\u{201d}é.env")),
            "Generic Password - /repo/a__(id)_id__PATH__x__.env"
        );
        assert_eq!(
            ignore_name(
                &s,
                &payload(EventType::PreToolUse, Some(Tool::Bash), "cat .env")
            ),
            "Generic Password"
        );
    }

    /// GIVEN two secrets found in a file the agent already read
    /// WHEN the block message is built
    /// THEN it names the file and lists the numbered remediation steps.
    #[test]
    fn post_tool_read_message_names_the_file_and_lists_remediation() {
        let secrets = vec![
            secret("AWS Keys", "valid", &["AKIAsomethingXYZ"]),
            secret("Generic Password", "unknown", &["hunter2hunter2"]),
        ];
        // VS Code cannot replace a tool output, so the secret really did reach
        // the model and this is the wording that must survive.
        let p = payload_for(
            crate::payload::Agent::VsCode,
            EventType::PostToolUse,
            Some(Tool::Read),
            "/tmp/creds.env",
        );
        let msg = from_secrets(&secrets, &p);
        assert!(
            msg.contains("Detected 2 secrets in /tmp/creds.env"),
            "{msg}"
        );
        assert!(msg.contains("Consider them compromised."));
        assert!(msg.contains("  1. revoke the secrets and issue new ones with their providers."));
        assert!(msg.contains("  2. consider moving the new secrets to a secrets manager."));
        assert!(!msg.contains("false positive"), "{msg}");
    }

    /// GIVEN a known secret with an incident URL
    /// WHEN the block message is built
    /// THEN the URL is listed and a third remediation step points at it.
    #[test]
    fn known_secrets_add_an_incident_url_and_a_third_step() {
        let mut s = secret("AWS Keys", "valid", &["AKIAsomethingXYZ"]);
        s.known_secret = true;
        s.incident_url = Some("https://dashboard.gitguardian.com/incidents/9".into());
        let p = payload_for(
            crate::payload::Agent::VsCode,
            EventType::PostToolUse,
            Some(Tool::Bash),
            "id",
        );
        let msg = from_secrets(&[s], &p);
        assert!(msg.contains("    Incident URL: https://dashboard.gitguardian.com/incidents/9"));
        assert!(
            msg.contains("  3. resolve the incident linked above in your GitGuardian dashboard.")
        );
    }

    /// GIVEN a secret in the prompt itself
    /// WHEN the block message is built
    /// THEN it uses the prompt wording and tells the user to resubmit.
    #[test]
    fn user_prompt_uses_its_own_template() {
        let p = payload(EventType::UserPrompt, None, "abc");
        let msg = from_secrets(&[secret("AWS Keys", "valid", &["AKIAsomething"])], &p);
        assert!(msg.contains("in your prompt"));
        assert!(msg.contains("  2. submit your prompt again."));
    }

    /// GIVEN a prompt mentioning a file, whose derived Read payload holds the secret
    /// WHEN the block message is built
    /// THEN it names the file rather than the prompt.
    #[test]
    fn file_mentioned_in_a_prompt_is_named_instead_of_the_prompt() {
        let p = payload(EventType::UserPrompt, Some(Tool::Read), "/tmp/config.py");
        let msg = from_secrets(&[secret("AWS Keys", "valid", &["AKIAsomething"])], &p);
        assert!(msg.contains("in /tmp/config.py"));
        assert!(!msg.contains("in your prompt"));
        assert!(!msg.contains("remove the secret from your prompt"));
    }

    /// GIVEN a secret in an output the agent let us replace
    /// WHEN the block message is built
    /// THEN it says the output was withheld and never tells the user to revoke.
    #[test]
    fn a_withheld_output_never_advises_revoking() {
        for (tool, expected) in [
            (Tool::Bash, "The command ran, but its output was withheld"),
            (Tool::Read, "The file content was withheld"),
        ] {
            let p = payload(EventType::PostToolUse, Some(tool), "/tmp/creds.env");
            let msg = from_secrets(&[secret("AWS Keys", "valid", &["AKIAsomething"])], &p);
            assert!(msg.contains(expected), "{tool:?}: {msg}");
            assert!(msg.contains("not sent to the model"), "{tool:?}: {msg}");
            assert!(!msg.contains("Consider it compromised"), "{tool:?}: {msg}");
            assert!(!msg.contains("revoke"), "{tool:?}: {msg}");
        }
    }

    /// GIVEN Claude Code, which has a channel only the user reads
    /// WHEN secrets of each validity mix are blocked
    /// THEN the model text never carries a way to ignore them, and the user gets
    /// the hint only for the secrets not checked as valid.
    #[test]
    fn claude_sends_the_false_positive_hint_to_the_user_only() {
        let valid = || secret("AWS Keys", "valid", &["AKIAsomething"]);
        let unchecked = || secret("Generic Password", "unknown", &["hunter2hunter2"]);
        let unchecked_sha = crate::api::ignore_sha(&unchecked().matches);
        let p = payload(EventType::PreToolUse, Some(Tool::Read), "/repo/.env");
        let command = format!(
            "    ggshield secret ignore {unchecked_sha} --name \"Generic Password - /repo/.env\""
        );
        let cases: [(&[Secret], &str); 3] = [
            (&[valid()], ""),
            (
                &[unchecked()],
                "> If this is a false positive, run at the root of the repository the agent works in:\n\n",
            ),
            (
                &[valid(), unchecked()],
                "> If the secret not marked valid is a false positive, run at the root of the repository the agent works in:\n\n",
            ),
        ];
        for (secrets, hint) in cases {
            let msg = from_secrets(secrets, &p);
            for leak in [
                "secret ignore",
                "ignored_matches",
                &unchecked_sha,
                "handling-false-positives",
            ] {
                assert!(!msg.contains(leak), "{leak}: {msg}");
            }
            assert!(msg.contains("> Instructions for the AI agent"), "{msg}");

            let user = user_message(secrets, &p);
            if hint.is_empty() {
                assert_eq!(user, "");
            } else {
                // Only the unchecked secret's command: the valid one is never offered.
                assert_eq!(user, format!("{hint}{command}"));
            }
        }
    }

    /// GIVEN every supported agent, every event, and each validity mix
    /// WHEN secrets are blocked
    /// THEN the model text carries the instructions and no false-positive hint,
    /// and the user gets the hint exactly once: in the user-only field where the
    /// agent has one, in the notification otherwise, and nowhere for a valid
    /// secret.
    #[test]
    fn every_agent_keeps_the_hint_from_the_model_and_gives_it_to_the_user() {
        let valid = || secret("AWS Keys", "valid", &["AKIAsomething"]);
        let unchecked = || secret("Generic Password", "unknown", &["hunter2hunter2"]);
        let cases: [(&[Secret], &str); 3] = [
            (&[valid()], ""),
            (
                &[unchecked()],
                "If this is a false positive, see \"Handling false positives\" in the ggshield AI hook docs.",
            ),
            (
                &[valid(), unchecked()],
                "If the secret not marked valid is a false positive, see \"Handling false positives\"",
            ),
        ];
        for agent in crate::payload::AGENTS {
            for event in [
                EventType::UserPrompt,
                EventType::PreToolUse,
                EventType::PostToolUse,
                EventType::Other,
            ] {
                let p = payload_for(agent, event, Some(Tool::Bash), "echo x");
                for (secrets, notification) in &cases {
                    let msg = from_secrets(secrets, &p);
                    for leak in [
                        "false positive",
                        "secret ignore",
                        "ignored_matches",
                        "- match:",
                    ] {
                        assert!(!msg.contains(leak), "{agent:?}/{event:?} {leak}: {msg}");
                    }
                    assert!(
                        msg.contains("> Instructions for the AI agent\n\n  Relay this notice to the user. Do not ignore the"),
                        "{agent:?}/{event:?}: {msg}"
                    );
                    assert!(
                        msg.ends_with(
                            "do not suggest disabling or uninstalling the GitGuardian hook."
                        ),
                        "{agent:?}/{event:?}: {msg}"
                    );

                    let user = user_message(secrets, &p);
                    let banner = notification_hint(secrets, &p);
                    if agent == crate::payload::Agent::Claude {
                        assert_eq!(banner, "", "{event:?}");
                        assert_eq!(
                            user.is_empty(),
                            notification.is_empty(),
                            "{event:?}: {user}"
                        );
                    } else {
                        assert_eq!(user, "", "{agent:?}/{event:?}");
                        assert!(banner.starts_with(notification), "{agent:?}: {banner}");
                        assert_eq!(banner.is_empty(), notification.is_empty(), "{agent:?}");
                        assert!(!banner.contains('\n'), "{agent:?}: {banner}");
                    }
                }
            }
        }
    }

    /// GIVEN the same secret in the same tool output on two agents
    /// WHEN one of them can replace the output and the other cannot
    /// THEN only the agent that cannot is told the secret was compromised.
    #[test]
    fn the_wording_follows_the_agent_not_the_event() {
        use crate::payload::Agent;
        let secrets = [secret("AWS Keys", "valid", &["AKIAsomething"])];
        // Codex on an MCP tool: a tool Claude could not redact, on an agent
        // that replaces every tool result. The wording tracks the agent.
        let withheld = from_secrets(
            &secrets,
            &payload_for(Agent::Codex, EventType::PostToolUse, Some(Tool::Mcp), "id"),
        );
        let leaked = from_secrets(
            &secrets,
            &payload_for(Agent::Cursor, EventType::PostToolUse, Some(Tool::Mcp), "id"),
        );
        assert!(withheld.contains("withheld from the agent"), "{withheld}");
        assert!(!withheld.contains("compromised"), "{withheld}");
        assert!(leaked.contains("Consider it compromised."), "{leaked}");
    }

    /// GIVEN every (event, tool) pair the dispatch table has an arm for
    /// WHEN the block message is built
    /// THEN each one lands on its own template, identified by its first line.
    #[test]
    fn every_event_and_tool_pair_picks_its_template() {
        use EventType::{Other as OtherEvent, PostToolUse, PreToolUse, UserPrompt};
        use Tool::{Bash, Mcp, Other as OtherTool, Read};
        let cases = [
            (UserPrompt, None, "in your prompt"),
            (UserPrompt, Some(Bash), "in your prompt"),
            (UserPrompt, Some(Mcp), "in your prompt"),
            // The prompt's own Read payload is about a file, not the prompt.
            (UserPrompt, Some(Read), "in the-identifier"),
            (PostToolUse, Some(Bash), "in the command output"),
            (PostToolUse, Some(Read), "in the-identifier"),
            (PostToolUse, Some(Mcp), "in the tool output"),
            (PostToolUse, Some(OtherTool), "in the tool output"),
            (PostToolUse, None, "in the tool output"),
            (PreToolUse, Some(Bash), "in the command"),
            (PreToolUse, Some(Read), "in the-identifier"),
            (PreToolUse, Some(Mcp), "in the tool input"),
            (PreToolUse, None, "in the tool input"),
            (OtherEvent, Some(Bash), "in the command"),
            (OtherEvent, Some(Read), "in the-identifier"),
            (OtherEvent, None, "in the tool input"),
        ];
        for (event_type, tool, expected) in cases {
            let p = payload(event_type, tool, "the-identifier");
            let msg = from_secrets(&[secret("AWS Keys", "valid", &["AKIAsomething"])], &p);
            let first_line = msg.lines().next().expect("a first line");
            assert!(
                first_line.contains(expected),
                "{event_type:?}/{tool:?}: {first_line}"
            );
        }
    }
}
