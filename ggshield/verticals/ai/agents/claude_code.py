import json
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Literal

import click
from pygitguardian.models import AIDiscovery, MCPActivityRequest

from ggshield.core.dirs import get_user_home_dir

from ..models import (
    Agent,
    EventType,
    HookPayload,
    HookResult,
    MCPConfiguration,
    Scope,
    Transport,
)


class Claude(Agent):
    """Behavior specific to Claude Code."""

    @property
    def name(self) -> str:
        return "claude-code"

    @property
    def display_name(self) -> str:
        return "Claude Code"

    @property
    def config_folder(self) -> Path:
        return get_user_home_dir() / ".claude"

    def output_result(self, result: HookResult) -> int:
        response = {}
        if result.block:
            if result.payload.event_type in [
                EventType.USER_PROMPT,
                EventType.POST_TOOL_USE,
            ]:
                response["decision"] = "block"
                response["reason"] = result.message
                response["additionalContext"] = result.message
            elif result.payload.event_type == EventType.PRE_TOOL_USE:
                response["hookSpecificOutput"] = {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": result.message,
                }
            else:
                # Should not happen, but just in case use Claude's "universal" fields.
                response = {
                    "continue": False,
                    "stopReason": result.message,
                }
        else:
            response["continue"] = True

        click.echo(json.dumps(response))
        # We don't use the return 2 convention to make sure our JSON output is read.
        return 0

    def is_caller(self, hook_payload: Dict[str, Any]) -> bool:
        return "session_id" in hook_payload and "claude" in hook_payload.get(
            "transcript_path", ""
        )

    def settings_path(self, mode: Literal["local", "global"]) -> Path:
        return Path(".claude") / "settings.json"

    @property
    def user_mcp_file(self) -> Path:
        return get_user_home_dir() / ".claude.json"

    def project_mcp_file(self, directory: Path) -> Path:
        return directory / ".mcp.json"

    def _get_user_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        """Yield user-scoped MCP configurations from every known Claude Code source."""
        yield from self._get_dot_claude_json_mcp_configurations()
        yield from self._get_plugin_mcp_configurations()
        yield from self._get_claudeai_mcp_configurations()

    def _get_dot_claude_json_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        """Look into ~/.claude.json for both user-level and project-level MCP server entries."""
        # Load config file
        data = self._load_file(self.user_mcp_file)
        if not data:
            return

        # User-level mcpServers
        yield from self._parse_servers_block(data, Scope.USER, None)

        # Per-project entries in projects dict (local scope: per-user, per-project)
        projects = data.get("projects", {})
        if not isinstance(projects, dict):
            return
        for project_key, project_data in projects.items():
            if not isinstance(project_data, dict):
                continue
            yield from self._parse_servers_block(
                project_data, Scope.USER, Path(project_key)
            )

    def _get_plugin_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        """Yield MCP servers contributed by installed Claude Code plugins.

        Plugins are tracked in ``~/.claude/plugins/installed_plugins.json``.
        Each plugin can declare MCP servers either in ``<installPath>/.mcp.json``
        or inline under the ``mcpServers`` key of
        ``<installPath>/.claude-plugin/plugin.json``.
        """
        installed_path = self.config_folder / "plugins" / "installed_plugins.json"
        if not (data := self._load_file(installed_path)):
            return

        plugins = data.get("plugins", {})
        if not isinstance(plugins, dict):
            return

        # Expected format: {plugin_id: [{installation1}, {installation2}, ...]}
        for installations in plugins.values():
            if not isinstance(installations, list):
                continue
            for installation in installations:
                if not isinstance(installation, dict):
                    continue
                yield from self._parse_plugin_installation(installation)

    def _parse_plugin_installation(
        self, installation: Dict[str, Any]
    ) -> Iterator[MCPConfiguration]:
        """Parse a single plugin installation entry and yield any MCP servers."""
        install_path = installation.get("installPath")
        if not isinstance(install_path, str):
            return
        install_dir = Path(install_path)
        if not install_dir.is_dir():
            return

        # Tie project/local-scoped plugins to their project. Local-scoped
        # plugins remain Scope.USER (per-user, per-project) to match the
        # convention used for ~/.claude.json[projects] entries.
        scope_str = installation.get("scope", "user")
        project_path = installation.get("projectPath")
        project = Path(project_path) if isinstance(project_path, str) else None
        scope = Scope.PROJECT if scope_str == "project" else Scope.USER

        # Preferred location: .mcp.json at the plugin root. The file may use
        # either the wrapped {"mcpServers": {...}} layout or the bare
        # {"name": {...}} layout, so we normalize before parsing.
        mcp_data = self._load_file(install_dir / ".mcp.json")
        if mcp_data is not None:
            if "mcpServers" not in mcp_data and "servers" not in mcp_data:
                mcp_data = {"mcpServers": mcp_data}
            yield from self._parse_servers_block(mcp_data, scope, project)
            return

        # Fallback: inline mcpServers in the plugin manifest.
        manifest = self._load_file(install_dir / ".claude-plugin" / "plugin.json")
        if not manifest:
            return
        inline = manifest.get("mcpServers")
        if isinstance(inline, dict):
            yield from self._parse_servers_block({"mcpServers": inline}, scope, project)

    def _get_claudeai_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        """Yield MCP servers connected through the user's claude.ai account.

        These are remote connectors hosted by Anthropic; we do not have their
        URLs locally, only their names. We collect names from two sources
        and deduplicate them:

        - claudeAiMcpEverConnected in ~/.claude.json (historical list)
        - ~/.claude/mcp-needs-auth-cache.json (currently-authorized list)
        """
        names: List[str] = []
        seen: set = set()

        def _add(name: str) -> None:
            name = name.removeprefix("claude.ai ")
            if name in seen:
                return
            seen.add(name)
            names.append(name)

        claude_json = self._load_file(get_user_home_dir() / ".claude.json")
        if claude_json:
            for name in claude_json.get("claudeAiMcpEverConnected", []) or []:
                _add(name)

        auth_cache = self._load_file(self.config_folder / "mcp-needs-auth-cache.json")
        if auth_cache:
            for name in auth_cache.keys():
                _add(name)

        for name in names:
            yield MCPConfiguration(
                name=name,
                agent=self.name,
                scope=Scope.USER,
                transport=Transport.HTTP,
                project=None,
                url="claude.ai",
            )

    def discover_project_directories(self) -> Iterator[Path]:
        """Discover project directories by scraping config files."""
        history_file = self.config_folder / "history.jsonl"
        projects = set()
        for line in self._load_jsonl_file(history_file):
            if "project" in line:
                projects.add(Path(line["project"]))
        for project in projects:
            if project.is_dir():
                yield project.resolve()

    def parse_mcp_activity(
        self, payload: HookPayload, ai_config: AIDiscovery
    ) -> MCPActivityRequest:
        """Parse the MCP activity from an MCP hook payload."""

        # Claude Code's hook tool name is "mcp__{server}__{tool}"
        raw_tool_name: str = payload.raw.get("tool_name", "")
        parts = raw_tool_name.split("__")
        # The server name can be anything, but we assume no MCP tool has a "__" in its name
        tool = parts[-1]
        server_cfg_name = "__".join(parts[1:-1])
        # Remove the optional "claude_ai_" prefix
        server_cfg_name = server_cfg_name.removeprefix("claude_ai_")

        # Lookup the server name based on its configuration name
        # Fallback to the server name if not found
        server_name = server_cfg_name
        for server in ai_config.servers:
            for configuration in server.configurations:
                if _mangle_server_name(configuration.name) == server_cfg_name:
                    server_name = server.name
                    break

        return MCPActivityRequest(
            user=ai_config.user,
            tool=tool,
            server=server_name,
            agent=self.name,
            model="",
            cwd=payload.raw.get("cwd", ""),
            input=payload.raw.get("tool_input", {}),
        )


MANGLING_PATTERN = re.compile(r"[^A-Za-z0-9-]")


def _mangle_server_name(name: str) -> str:
    """Mangle a server name in the same way Claude Code does."""
    return MANGLING_PATTERN.sub("_", name)
