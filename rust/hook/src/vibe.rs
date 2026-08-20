//! Vibe's `post_process_payload()`, from `ggshield/verticals/ai/agents/vibe.py`.
//!
//! Vibe names an MCP tool `{server}_{tool}`, with no `mcp` prefix to key off, so
//! `parse_tool()` gets it wrong in both directions — `github_create_issue` reads
//! as an ordinary tool, and one of Vibe's own tools starting with "mcp" reads as
//! MCP — and only the configured server names can settle it.
//!
//! `is_mcp_activity_payload()` gates MCP activity on this classification, and
//! that call is itself unported (see the KNOWN LIMITATION on `scan_payloads` in
//! lib.rs), so nothing observable depends on it yet.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::payload::{Payload, Tool};

/// `Vibe.config_folder`: `$VIBE_HOME`, else `~/.vibe`.
fn config_folder() -> Option<PathBuf> {
    if let Ok(home) = std::env::var("VIBE_HOME")
        && !home.is_empty()
    {
        return Some(expand_user(&home, ggshield_config::user_config::home_dir()));
    }
    // `get_user_home_dir()`, GG_USER_HOME_DIR included.
    ggshield_config::user_config::home_dir().map(|home| home.join(".vibe"))
}

/// `Path.expanduser()` for a leading `~`, which `std::path` leaves alone.
///
/// `~user` needs a passwd lookup, so it stays a literal directory name; Python
/// would resolve it, and a `VIBE_HOME` of that shape is the one case that still
/// diverges.
fn expand_user(path: &str, home: Option<PathBuf>) -> PathBuf {
    let Some(rest) = path.strip_prefix('~') else {
        return PathBuf::from(path);
    };
    let tail = rest.trim_start_matches(['/', '\\']);
    // A `~` that is not alone and not followed by a separator names a user.
    if !rest.is_empty() && tail.len() == rest.len() {
        return PathBuf::from(path);
    }
    match home {
        Some(home) if tail.is_empty() => home,
        Some(home) => home.join(tail),
        None => PathBuf::from(path),
    }
}

/// The `name` of every server in a `config.toml`'s `mcp_servers` array.
///
/// Anything unreadable, unparsable or the wrong shape yields nothing rather than
/// failing the hook, as `_load_file()` does. The `Value` is walked by hand rather
/// than deserialized into a struct so that, like `vibe.py`, one malformed entry
/// is skipped instead of discarding every server in the file.
fn server_names(path: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    // `toml::from_str`, NOT `text.parse::<Value>()`: the latter parses a single
    // TOML *value*, so it reads a leading `[[mcp_servers]]` as an array literal
    // and rejects the rest of the file as trailing content.
    let Ok(value) = toml::from_str::<toml::Value>(&text) else {
        return Vec::new();
    };
    let Some(servers) = value.get("mcp_servers").and_then(toml::Value::as_array) else {
        return Vec::new();
    };
    servers
        .iter()
        .filter_map(|entry| entry.get("name")?.as_str().map(str::to_string))
        .collect()
}

/// `Vibe._match_mcp_tool_name()`, reduced to the only question asked here: does
/// any configured server own this tool name? Python's longest-first sort only
/// decides *which* server matched, so it is left out until
/// `parse_mcp_activity()` is ported and needs the server's identity.
fn is_mcp_tool_name(raw_tool_name: &str, names: &[String]) -> bool {
    names
        .iter()
        .any(|name| raw_tool_name.starts_with(&format!("{name}_")))
}

/// `Vibe.post_process_payload()`.
pub fn post_process(payload: &mut Payload) {
    // Only MCP and OTHER are in play: re-deciding Bash or Read would undo a
    // synthesised read.
    if !matches!(payload.tool, Some(Tool::Mcp) | Some(Tool::Other)) {
        return;
    }
    let raw_tool_name = payload
        .raw
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let cwd = payload
        .raw
        .get("cwd")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let mut names = Vec::new();
    if let Some(folder) = config_folder() {
        names.extend(server_names(&folder.join("config.toml")));
    }
    if !cwd.is_empty() {
        names.extend(server_names(
            &Path::new(cwd).join(".vibe").join("config.toml"),
        ));
    }

    // Undo the generic "mcp" prefix heuristic unless a configured server really
    // owns the name, so a custom tool called `mcp_*` is not reported as MCP.
    payload.tool = Some(if is_mcp_tool_name(raw_tool_name, &names) {
        Tool::Mcp
    } else {
        Tool::Other
    });
}

/// `VIBE_HOME` is process-wide, so every test that pins it takes this one lock.
#[cfg(test)]
static VIBE_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Points `VIBE_HOME` at an empty directory, so a `~/.vibe/config.toml` on
    /// the machine running the tests cannot add servers to the ones under test.
    fn with_empty_vibe_home() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        let guard = VIBE_ENV.lock().unwrap_or_else(|error| error.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        // SAFETY: serialised by the mutex above.
        unsafe { std::env::set_var("VIBE_HOME", dir.path()) };
        (guard, dir)
    }

    /// GIVEN a `VIBE_HOME` written with a leading `~`
    /// WHEN it is expanded
    /// THEN only a bare `~` or a `~/` prefix resolves, and `~user` stays literal.
    #[test]
    fn only_a_bare_tilde_or_a_tilde_slash_expands() {
        let home = Some(PathBuf::from("/home/me"));
        assert_eq!(expand_user("~", home.clone()), PathBuf::from("/home/me"));
        assert_eq!(
            expand_user("~/.vibe", home.clone()),
            PathBuf::from("/home/me/.vibe")
        );
        // Not a tilde path at all.
        assert_eq!(
            expand_user("/tmp/vibe", home.clone()),
            PathBuf::from("/tmp/vibe")
        );
        // `~user` is a passwd lookup we do not do, so it stays as written.
        assert_eq!(
            expand_user("~other/.vibe", home),
            PathBuf::from("~other/.vibe")
        );
        // Without a home there is nothing to substitute.
        assert_eq!(expand_user("~/.vibe", None), PathBuf::from("~/.vibe"));
    }

    /// GIVEN a tool name and a set of configured servers
    /// WHEN each is matched
    /// THEN only the `{server}_` prefix counts — a bare server name, a different
    /// separator, or a server that is merely a substring are all misses.
    #[test]
    fn only_a_server_prefix_makes_a_tool_an_mcp_tool() {
        let names = vec!["github".to_string(), "my_server".to_string()];
        assert!(is_mcp_tool_name("github_create_issue", &names));
        assert!(is_mcp_tool_name("my_server_do_thing", &names));
        // The separator is required: the bare name is not a tool call.
        assert!(!is_mcp_tool_name("github", &names));
        assert!(!is_mcp_tool_name("github-create_issue", &names));
        assert!(!is_mcp_tool_name("gitlab_create_issue", &names));
        assert!(!is_mcp_tool_name("mcp_something", &names));
        assert!(!is_mcp_tool_name("anything", &[]));
    }

    /// GIVEN a Vibe `config.toml`, and files that are missing, malformed or the
    /// wrong shape
    /// WHEN the server names are read
    /// THEN the good one yields its names and none of the others raise.
    #[test]
    fn unreadable_or_malformed_config_yields_no_names() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let good = tmp.path().join("config.toml");
        std::fs::write(
            &good,
            r#"
            [[mcp_servers]]
            name = "github"
            transport = "stdio"
            command = "docker"

            [[mcp_servers]]
            name = "sentry"
            url = "https://mcp.sentry.dev"
            "#,
        )
        .expect("write");
        assert_eq!(server_names(&good), vec!["github", "sentry"]);

        // Missing file.
        assert!(server_names(&tmp.path().join("absent.toml")).is_empty());
        // Not TOML at all.
        let bad = tmp.path().join("bad.toml");
        std::fs::write(&bad, "{not toml").expect("write");
        assert!(server_names(&bad).is_empty());
        // Valid TOML, no mcp_servers.
        let other = tmp.path().join("other.toml");
        std::fs::write(&other, "model = \"large\"\n").expect("write");
        assert!(server_names(&other).is_empty());
        // mcp_servers present but entries have no usable name.
        let nameless = tmp.path().join("nameless.toml");
        std::fs::write(&nameless, "[[mcp_servers]]\ncommand = \"x\"\n").expect("write");
        assert!(server_names(&nameless).is_empty());
    }

    fn payload_named(tool_name: &str, tool: Tool, cwd: &str) -> Payload {
        Payload {
            event_type: crate::payload::EventType::PreToolUse,
            tool: Some(tool),
            content: String::new(),
            identifier: "id".into(),
            agent: crate::payload::Agent::Vibe,
            raw: json!({"tool_name": tool_name, "cwd": cwd}),
            read_range: None,
            cwd: cwd.into(),
        }
    }

    /// GIVEN a project `.vibe/config.toml` declaring one server
    /// WHEN a call to that server and a lookalike are post-processed
    /// THEN only the configured one becomes MCP, and a tool merely named `mcp_*`
    /// is demoted.
    #[test]
    fn project_config_decides_which_tools_are_mcp() {
        let (_vibe_home, _empty) = with_empty_vibe_home();
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join(".vibe");
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(
            dir.join("config.toml"),
            "[[mcp_servers]]\nname = \"github\"\n",
        )
        .expect("write");
        let cwd = tmp.path().to_string_lossy().to_string();

        let mut p = payload_named("github_create_issue", Tool::Other, &cwd);
        post_process(&mut p);
        assert_eq!(p.tool, Some(Tool::Mcp));

        // Named like the generic heuristic expects, but no server owns it.
        let mut p = payload_named("mcp_lookalike", Tool::Mcp, &cwd);
        post_process(&mut p);
        assert_eq!(p.tool, Some(Tool::Other));

        // A settled classification is never revisited.
        let mut p = payload_named("github_create_issue", Tool::Read, &cwd);
        post_process(&mut p);
        assert_eq!(p.tool, Some(Tool::Read));
    }
}
