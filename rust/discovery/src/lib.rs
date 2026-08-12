//! The AI inventory ggshield's discovery walk leaves in `ai_discovery.json`:
//! who the user is, and which MCP servers the API knows about. The walk itself
//! stays in Python; this only reads what it wrote.
//!
//! Freshness is load-bearing. `refresh_and_maybe_submit_discovery()` rewrites the
//! file with a one hour TTL, so a fresh file is this session's walk, reconciled
//! server names included. A stale or absent one means there *is* no inventory,
//! and a caller must decline rather than invent one: the server names in here are
//! what an organisation's policies are written against.
//!
//! Separate from the hook crate — `ggshield ai discover`, the history backfill
//! and agent activity all read the same file.

use std::path::Path;
use std::time::{Duration, SystemTime};

use serde::Deserialize;

use ggshield_common::secure_file;
use ggshield_config::config;

/// `AI_DISCOVERY_CACHE_FILENAME` in cache.py, in the same cache directory.
const FILENAME: &str = "ai_discovery.json";

/// `DISCOVERY_CACHE_TTL_SECONDS`.
const TTL: Duration = Duration::from_secs(3600);

/// `MTIME_SKEW_TOLERANCE_SECONDS`. The wall clock and the filesystem mtime do not
/// come from the same source, so a just-touched file can read marginally in the
/// future. Tolerate that much, while still treating a real clock jump as stale
/// rather than pinning the inventory fresh forever.
const MTIME_SKEW_TOLERANCE: Duration = Duration::from_secs(5);

/// `UserInfo`. Sent verbatim with every activity report, so it is read rather
/// than recomputed: `machine_id` is generated once and persisted here, and
/// regenerating it would split one machine's history in two.
#[derive(Debug, Clone, Deserialize)]
pub struct User {
    pub hostname: String,
    pub username: String,
    pub machine_id: String,
    #[serde(default)]
    pub user_email: Option<String>,
}

/// One assistant's declaration of a server. Several can point at the same
/// [`Server`], so a mangled name is a *configuration* name, not a server name.
#[derive(Debug, Deserialize)]
pub struct Configuration {
    pub name: String,
    pub agent: String,
}

#[derive(Debug, Deserialize)]
pub struct Tool {
    pub name: String,
}

/// `MCPServer`. `name` is the canonical one — the dashboard's, once the API has
/// reconciled the walk — and the only name a policy can be written against.
#[derive(Debug, Deserialize)]
pub struct Server {
    pub name: String,
    #[serde(default)]
    pub tools: Vec<Tool>,
    #[serde(default)]
    pub configurations: Vec<Configuration>,
}

/// `AIDiscovery`, minus the fields no per-tool-call decision reads. Unknown
/// fields are ignored, so the file Python writes deserializes as is.
#[derive(Debug, Deserialize)]
pub struct Inventory {
    pub user: User,
    #[serde(default)]
    pub servers: Vec<Server>,
}

/// The inventory, but only while it is fresh.
///
/// `None` covers every reason there is no usable inventory — no file, a file
/// another user could have written, unparseable content, a walk older than the
/// TTL — because they all mean the same thing to a caller: nothing here is
/// trustworthy enough to decide with.
pub fn load_fresh() -> Option<Inventory> {
    let path = config::cache_dir()?.join(FILENAME);
    if !is_fresh(&path) {
        return None;
    }
    serde_json::from_str(&secure_file::read_if_trusted(&path)?).ok()
}

/// `is_discovery_cache_fresh()`: refreshed less than the TTL ago, allowing for
/// clock skew in the other direction.
fn is_fresh(path: &Path) -> bool {
    let Ok(mtime) = std::fs::metadata(path).and_then(|meta| meta.modified()) else {
        return false;
    };
    match SystemTime::now().duration_since(mtime) {
        Ok(age) => age < TTL,
        Err(ahead) => ahead.duration() <= MTIME_SKEW_TOLERANCE,
    }
}

/// `_mangle_server_name()`: Claude Code (and Codex) replace every character
/// outside `[A-Za-z0-9-]` with an underscore, one for one.
fn mangle_claude(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// VS Code mangles harder: *runs* of those characters collapse into a single
/// underscore, the result is lower-cased, and only the first 13 characters
/// survive. Two configurations can therefore mangle to the same key.
fn mangle_vscode(name: &str) -> String {
    let mut out = String::new();
    let mut in_run = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '-' {
            out.push(c.to_ascii_lowercase());
            in_run = false;
        } else if !in_run {
            out.push('_');
            in_run = true;
        }
    }
    out.chars().take(13).collect()
}

/// Copilot CLI lower-cases and replaces every non-word character with a hyphen.
///
/// Python then IDNA-encodes the result, which is the identity for an ASCII name
/// and punycode for anything else. Not reproduced: a non-ASCII configuration name
/// falls through to the positional split below, the same answer Python gives for
/// any name it cannot find in the inventory.
fn mangle_copilot(name: &str) -> String {
    name.chars()
        .flat_map(char::to_lowercase)
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

impl Inventory {
    fn configurations(&self) -> impl DoubleEndedIterator<Item = (&Server, &Configuration)> {
        self.servers
            .iter()
            .flat_map(|server| server.configurations.iter().map(move |conf| (server, conf)))
    }

    /// `_resolve_server_name()`: the canonical server behind a Claude Code or
    /// Codex configuration name, falling back to the configuration name for a
    /// server the walk has not seen yet.
    pub fn server_for_config_name(&self, cfg_name: &str) -> String {
        self.configurations()
            .find(|(_, conf)| mangle_claude(&conf.name) == cfg_name)
            .map_or_else(|| cfg_name.to_string(), |(server, _)| server.name.clone())
    }

    /// Cursor names only the tool, so the server is whichever discovered one owns
    /// a tool by that name. The *last* such server wins, as Python's dict build
    /// leaves it; duplicate tool names across servers are unresolvable either way.
    pub fn server_for_tool_name(&self, tool: &str) -> String {
        self.servers
            .iter()
            .rfind(|server| server.tools.iter().any(|owned| owned.name == tool))
            .map_or_else(String::new, |server| server.name.clone())
    }

    /// `_lookup_server_name()`: split `mcp_<server>_<tool>`, where both halves can
    /// contain the separator, so the widest prefix that is a known configuration
    /// wins. Returns `(server, tool)`.
    ///
    /// On a prefix two configurations mangle to alike — easy to reach, since
    /// truncating to 13 characters is enough to collide — the *last* one wins, as
    /// Python's map build leaves it. Answering with the other server would check the
    /// call against a policy written for something else.
    pub fn split_underscored(&self, raw_tool_name: &str) -> (String, String) {
        // Drops the "mcp" prefix, as Python's `_, *parts` does.
        let parts: Vec<&str> = raw_tool_name.split('_').skip(1).collect();
        self.split_on(&parts, "_", |candidate| {
            self.configurations()
                .rfind(|(_, conf)| mangle_vscode(&conf.name) == candidate)
                .map(|(server, _)| server.name.clone())
        })
        // No prefix matched: the first part is the server and the rest the tool.
        .unwrap_or_else(|| match parts.split_first() {
            Some((first, rest)) => (first.to_string(), rest.join("_")),
            None => (String::new(), String::new()),
        })
    }

    /// The same walk, and the same last-one-wins, for Copilot CLI's
    /// `<server>-<tool>`, whose configuration names really do contain hyphens.
    /// Restricted to `agent`'s own configurations: Copilot cannot import another
    /// assistant's servers.
    pub fn split_hyphenated(&self, raw_tool_name: &str, agent: &str) -> (String, String) {
        let parts: Vec<&str> = raw_tool_name.split('-').collect();
        self.split_on(&parts, "-", |candidate| {
            // Lower-cased because Copilot preserves the case of the tool name
            // while the mangled key does not.
            let candidate = candidate.to_lowercase();
            self.configurations()
                .rfind(|(_, conf)| conf.agent == agent && mangle_copilot(&conf.name) == candidate)
                .map(|(server, _)| server.name.clone())
        })
        // No prefix matched: everything but the last part is the server name.
        .unwrap_or_else(|| match parts.split_last() {
            Some((tool, head)) => (head.join("-"), tool.to_string()),
            None => (String::new(), String::new()),
        })
    }

    /// The widest prefix of `parts` that `resolve` recognises, and the rest as the
    /// tool name.
    ///
    /// Widest is `parts` minus its last element, never the whole of it: Python
    /// starts its loop at `parts[:-0]` == `parts[:0]`, the *empty* prefix, so a
    /// configuration can never claim the entire name.
    fn split_on(
        &self,
        parts: &[&str],
        separator: &str,
        resolve: impl Fn(&str) -> Option<String>,
    ) -> Option<(String, String)> {
        (1..parts.len()).rev().find_map(|head_len| {
            let (head, tail) = parts.split_at(head_len);
            resolve(&head.join(separator)).map(|server| (server, tail.join(separator)))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `GG_CACHE_DIR` is process-wide, so the tests that point it somewhere else
    /// take this lock.
    static CACHE_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_cache_dir() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        let guard = CACHE_ENV.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().expect("tempdir");
        // SAFETY: serialised by the mutex above.
        unsafe { std::env::set_var("GG_CACHE_DIR", dir.path()) };
        (guard, dir)
    }

    /// One `ai_discovery.json` in the shape ggshield writes, with a few keys this
    /// crate must ignore.
    const CACHE: &str = r#"{
        "user": {"hostname": "laptop", "username": "dev",
                 "machine_id": "m-1", "user_email": null},
        "discovery_duration": 1.5,
        "agents": [{"name": "claude-code", "hooks_installed": true}],
        "servers": [
            {"name": "GitHub", "display_name": "GitHub", "resources": [], "prompts": [],
             "tools": [{"name": "delete_repository"}],
             "configurations": [
                {"name": "git hub", "agent": "claude-code", "scope": "user",
                 "transport": "stdio", "project": null},
                {"name": "git.hub", "agent": "copilot", "scope": "user",
                 "transport": "stdio", "project": null}]},
            {"name": "Sentry",
             "tools": [{"name": "find_issues"}],
             "configurations": [
                {"name": "sentry-prod", "agent": "vscode", "scope": "user",
                 "transport": "http"}]}
        ]
    }"#;

    fn inventory() -> Inventory {
        serde_json::from_str(CACHE).expect("the shipped shape parses")
    }

    /// GIVEN an `ai_discovery.json` carrying fields this crate does not read
    /// WHEN it is deserialized
    /// THEN the user and the servers come through and the rest is ignored.
    #[test]
    fn the_python_cache_shape_deserializes() {
        let inventory = inventory();
        assert_eq!(inventory.user.machine_id, "m-1");
        assert_eq!(inventory.user.user_email, None);
        assert_eq!(inventory.servers.len(), 2);
        assert_eq!(inventory.servers[0].configurations[1].agent, "copilot");
    }

    /// GIVEN a fresh cache file, then one aged past the TTL, then none at all
    /// WHEN a fresh inventory is asked for
    /// THEN only the first answers. A stale or absent walk must read as "no
    /// inventory", never as an empty one, which resolves every server name to a
    /// guess.
    #[test]
    fn only_a_fresh_cache_loads() {
        let (_guard, dir) = with_cache_dir();
        let path = dir.path().join(FILENAME);
        assert!(load_fresh().is_none(), "no file at all");

        secure_file::write_private(&path, CACHE).expect("write");
        assert!(load_fresh().is_some(), "just written");

        let stale = SystemTime::now() - TTL - Duration::from_secs(1);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .expect("open")
            .set_modified(stale)
            .expect("set mtime");
        assert!(load_fresh().is_none(), "older than the TTL");
    }

    /// GIVEN mtimes on both sides of "now"
    /// WHEN freshness is tested
    /// THEN the tolerance covers a file that reads marginally in the future, but a
    /// clock jump does not pin the inventory fresh forever.
    #[test]
    fn a_future_mtime_is_tolerated_only_within_the_skew() {
        let (_guard, dir) = with_cache_dir();
        let path = dir.path().join(FILENAME);
        secure_file::write_private(&path, CACHE).expect("write");
        let touch = |offset: Duration, ahead: bool| {
            let when = if ahead {
                SystemTime::now() + offset
            } else {
                SystemTime::now() - offset
            };
            std::fs::File::options()
                .write(true)
                .open(&path)
                .expect("open")
                .set_modified(when)
                .expect("set mtime");
            is_fresh(&path)
        };
        assert!(touch(Duration::from_secs(1), true), "within the skew");
        assert!(!touch(Duration::from_secs(600), true), "a clock jump");
        assert!(touch(TTL - Duration::from_secs(10), false), "just in time");
        assert!(!touch(TTL + Duration::from_secs(10), false), "expired");
    }

    /// GIVEN a cache file another local user could write
    /// WHEN the inventory is loaded
    /// THEN it is refused: the server names in it decide which policy applies.
    #[cfg(unix)]
    #[test]
    fn a_widely_writable_cache_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let (_guard, dir) = with_cache_dir();
        let path = dir.path().join(FILENAME);
        secure_file::write_private(&path, CACHE).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        assert!(load_fresh().is_none());
    }

    /// GIVEN a Claude Code or Codex configuration name, as those agents mangle it
    /// WHEN the server is resolved
    /// THEN it is the canonical name, and an unknown configuration keeps its own.
    #[test]
    fn a_mangled_configuration_name_resolves_to_the_canonical_server() {
        let inventory = inventory();
        // "git hub" reaches us as "git_hub".
        assert_eq!(inventory.server_for_config_name("git_hub"), "GitHub");
        assert_eq!(inventory.server_for_config_name("unheard-of"), "unheard-of");
    }

    /// GIVEN a tool name, which is all Cursor reports
    /// WHEN the server is resolved
    /// THEN the server owning that tool answers, and an unknown tool resolves to
    /// no server rather than to a guess.
    #[test]
    fn cursor_resolves_the_server_from_the_tool_it_owns() {
        let inventory = inventory();
        assert_eq!(inventory.server_for_tool_name("find_issues"), "Sentry");
        assert_eq!(inventory.server_for_tool_name("no_such_tool"), "");
    }

    /// GIVEN VS Code tool names whose server and tool halves both contain "_"
    /// WHEN they are split
    /// THEN the widest prefix that is a known configuration wins, and with no
    /// match the first part is taken as the server.
    #[test]
    fn vscode_splits_on_the_widest_known_configuration() {
        let inventory = inventory();
        // "sentry-prod" mangles to itself: 11 characters, already lower case.
        assert_eq!(
            inventory.split_underscored("mcp_sentry-prod_find_issues"),
            ("Sentry".to_string(), "find_issues".to_string())
        );
        // Nothing matches: the first part is the server, the rest the tool.
        assert_eq!(
            inventory.split_underscored("mcp_other_do_a_thing"),
            ("other".to_string(), "do_a_thing".to_string())
        );
        // A configuration can never claim the whole name: no tool left to report.
        assert_eq!(
            inventory.split_underscored("mcp_sentry-prod"),
            ("sentry-prod".to_string(), String::new())
        );
    }

    /// GIVEN Copilot CLI tool names, whose separator also occurs in the server
    /// configuration name
    /// WHEN they are split
    /// THEN the mangled configuration matches case-insensitively, only for
    /// Copilot's own configurations, and the fallback keeps the last part as the
    /// tool.
    #[test]
    fn copilot_splits_on_its_own_configurations_only() {
        let inventory = inventory();
        // "git.hub" mangles to "git-hub", and Copilot preserves the tool's case.
        assert_eq!(
            inventory.split_hyphenated("git-hub-delete_repository", "copilot"),
            ("GitHub".to_string(), "delete_repository".to_string())
        );
        // That configuration is Copilot's, not VS Code's, so the split falls back.
        assert_eq!(
            inventory.split_hyphenated("git-hub-delete_repository", "vscode"),
            ("git-hub".to_string(), "delete_repository".to_string())
        );
    }

    /// Two servers whose configuration names mangle to the same VS Code key
    /// ("github_enterp", both truncated at 13 characters) and the same Copilot key
    /// ("github-enterprise").
    const COLLIDING: &str = r#"{
        "user": {"hostname": "laptop", "username": "dev",
                 "machine_id": "m-1", "user_email": null},
        "servers": [
            {"name": "GitHub-Public",
             "configurations": [
                {"name": "GitHub Enterprise", "agent": "vscode"},
                {"name": "GitHub Enterprise", "agent": "copilot"}]},
            {"name": "GitHub-Internal",
             "configurations": [
                {"name": "GitHub Enterprise Prod", "agent": "vscode"},
                {"name": "GitHub.Enterprise", "agent": "copilot"}]}
        ]
    }"#;

    /// GIVEN a mangled prefix two configurations resolve to
    /// WHEN a VS Code or Copilot tool name is split on it
    /// THEN the last of them answers, which is the server Python's map build names.
    /// The other one is a different server with a different policy: reporting it
    /// would have the API permit a call an administrator denied.
    #[test]
    fn colliding_mangled_names_resolve_to_the_last_configuration() {
        let inventory: Inventory = serde_json::from_str(COLLIDING).expect("parses");
        assert_eq!(
            inventory.split_underscored("mcp_github_enterp_delete_repository"),
            (
                "GitHub-Internal".to_string(),
                "delete_repository".to_string()
            )
        );
        assert_eq!(
            inventory.split_hyphenated("github-enterprise-delete_repository", "copilot"),
            (
                "GitHub-Internal".to_string(),
                "delete_repository".to_string()
            )
        );
    }

    /// GIVEN each agent's mangling of one server configuration name
    /// WHEN it is applied
    /// THEN it matches that agent's own rules: one underscore per character for
    /// Claude Code, collapsed and truncated for VS Code, hyphens and lower case
    /// for Copilot.
    #[test]
    fn each_agent_mangles_a_name_its_own_way() {
        assert_eq!(mangle_claude("My Server.v2"), "My_Server_v2");
        // Runs collapse, lower case, and cut at 13 characters.
        assert_eq!(mangle_vscode("My  Server.v2 is long"), "my_server_v2_");
        assert_eq!(mangle_copilot("My Server.v2"), "my-server-v2");
        // A hyphen is not a word character for Copilot, but it maps to itself.
        assert_eq!(mangle_copilot("claude-ai"), "claude-ai");
    }
}
