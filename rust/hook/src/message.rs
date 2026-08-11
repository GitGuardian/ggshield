//! The block message shown to the user, and the little text helpers it needs.
//! Mirrors the templates and `_message_from_secrets()` in `hooks.py`.
//!
//! Every line of prose lives in `templates/`, and a template file *is* the text
//! it renders: no trailing newline, and the two spaces some lines end with are
//! markdown hard breaks (see [`HARD_BREAK`]) that an editor must not strip.
//! `render()` only substitutes `{placeholders}`; nothing here reformats a
//! template at runtime.

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
const SECRET_LINE_TEMPLATE: &str = include_str!("templates/secret_line.in");
const INCIDENT_URL_LINE_TEMPLATE: &str = include_str!("templates/incident_url_line.in");
const REMEDIATION_STEPS_TEMPLATE: &str = include_str!("templates/remediation_steps.in");
const REMEDIATION_STEPS_WITH_INCIDENT_TEMPLATE: &str =
    include_str!("templates/remediation_steps_with_incident.in");
const FALSE_POSITIVE_TEMPLATE: &str = include_str!("templates/false_positive.in");

/// Agents render the message as markdown, where a single newline collapses into a
/// space. Two trailing spaces keep the break. The templates carry it literally at
/// the end of a line; the lines of a list are joined with it — never after the
/// last one, which the templates always follow with a blank line.
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

/// One bullet per secret, plus its incident URL when we know one.
///
/// The censoring asterisks become bullets: the message is rendered as markdown,
/// where a pair of them would turn into emphasis.
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
/// Called only with at least one secret — `scan()` returns before this otherwise —
/// which is what lets the templates hard-break into the secret list.
pub fn from_secrets(secrets: &[Secret], payload: &Payload) -> String {
    let template = match (payload.event_type, payload.tool) {
        // A UserPrompt event also carries a Tool::Read payload per file
        // mentioned in the prompt. The secret is in that file, not in the
        // prompt, so the prompt wording would name the wrong content and its
        // remediation would tell the user to edit a prompt that is already clean.
        (EventType::UserPrompt, Some(Tool::Read)) => PRE_READ_TEMPLATE,
        (EventType::UserPrompt, _) => USER_PROMPT_TEMPLATE,
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
    // The words first: the blocks below are rendered from the very same fields.
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
        (
            "this_is",
            pluralize(
                "this is a false positive",
                count,
                Some("these are false positives"),
            ),
        ),
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
        "false_positive_instructions",
        render(FALSE_POSITIVE_TEMPLATE, &fields),
    ));
    render(template, &fields)
}

/// One pass, like `str.format`. Chained `replace` calls would re-scan text just
/// inserted, letting a server-supplied detector name containing `{were}` reach
/// into the template.
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
        Payload {
            event_type,
            tool,
            content: String::new(),
            identifier: identifier.into(),
            agent: crate::payload::Agent::Claude,
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
    /// THEN none holds a carriage return, so a CRLF checkout cannot put CRLF in
    /// the messages we print. `.gitattributes` pins them to LF; this catches a
    /// template that escapes that rule.
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
    /// THEN it is the PreToolUse/Bash wording, with the match censored into
    /// markdown-safe bullets.
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
        assert!(msg.ends_with("    ggshield secret ignore --last-found"));
    }

    /// GIVEN two secrets found in a file the agent already read
    /// WHEN the block message is built
    /// THEN it names the file, says they are compromised, and lists the numbered
    /// remediation steps.
    #[test]
    fn post_tool_read_message_names_the_file_and_lists_remediation() {
        let secrets = vec![
            secret("AWS Keys", "valid", &["AKIAsomethingXYZ"]),
            secret("Generic Password", "unknown", &["hunter2hunter2"]),
        ];
        let p = payload(EventType::PostToolUse, Some(Tool::Read), "/tmp/creds.env");
        let msg = from_secrets(&secrets, &p);
        assert!(
            msg.contains("Detected 2 secrets in /tmp/creds.env"),
            "{msg}"
        );
        assert!(msg.contains("Consider them compromised."));
        assert!(msg.contains("  1. revoke the secrets and issue new ones with their providers."));
        assert!(msg.contains("  2. consider moving the new secrets to a secrets manager."));
        assert!(msg.contains("> If these are false positives, run:"));
    }

    /// GIVEN a known secret with an incident URL
    /// WHEN the block message is built
    /// THEN the URL is listed and a third remediation step points at it.
    #[test]
    fn known_secrets_add_an_incident_url_and_a_third_step() {
        let mut s = secret("AWS Keys", "valid", &["AKIAsomethingXYZ"]);
        s.known_secret = true;
        s.incident_url = Some("https://dashboard.gitguardian.com/incidents/9".into());
        let p = payload(EventType::PostToolUse, Some(Tool::Bash), "id");
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
    /// THEN it names the file rather than telling the user to edit a prompt that is
    /// already clean.
    #[test]
    fn file_mentioned_in_a_prompt_is_named_instead_of_the_prompt() {
        let p = payload(EventType::UserPrompt, Some(Tool::Read), "/tmp/config.py");
        let msg = from_secrets(&[secret("AWS Keys", "valid", &["AKIAsomething"])], &p);
        assert!(msg.contains("in /tmp/config.py"));
        assert!(!msg.contains("in your prompt"));
        assert!(!msg.contains("remove the secret from your prompt"));
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
