import json
from pathlib import Path
from typing import Any, Dict, Iterator, Literal

import click
from pygitguardian.models import AIDiscovery, MCPActivityRequest

from ggshield.core.dirs import get_user_home_dir

from ..models import Agent, EventType, HookPayload, HookResult, MCPConfiguration, Scope
from .claude_code import _mangle_server_name


class Codex(Agent):
    """Behavior specific to OpenAI Codex."""

    @property
    def name(self) -> str:
        return "codex"

    @property
    def display_name(self) -> str:
        return "Codex"

    @property
    def config_folder(self) -> Path:
        return get_user_home_dir() / ".codex"

    def output_result(self, result: HookResult) -> int:
        response: Dict[str, Any] = {}
        if result.block:
            response["systemMessage"] = result.message
            if result.payload.event_type == EventType.PRE_TOOL_USE:
                response["hookSpecificOutput"] = {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": result.message,
                }
            elif result.payload.event_type in [
                EventType.USER_PROMPT,
                EventType.POST_TOOL_USE,
            ]:
                response["decision"] = "block"
                response["reason"] = result.message
            else:
                click.echo(result.message, err=True)
                return 2

        click.echo(json.dumps(response))
        return 0

    def is_caller(self, hook_payload: Dict[str, Any]) -> bool:
        return (
            "turn_id" in hook_payload
            or ".codex" in hook_payload.get("transcript_path", "").lower()
        )

    def settings_path(self, mode: Literal["local", "global"]) -> Path:
        return Path(".codex") / "hooks.json"

    def project_mcp_file(self, directory: Path) -> Path:
        return directory / ".codex" / "config.toml"

    @property
    def user_mcp_file(self) -> Path:
        return self.config_folder / "config.toml"

    def discover_project_directories(self) -> Iterator[Path]:
        data = self._load_file(self.config_folder / "config.toml")
        if not data:
            return
        for project in data.get("projects", {}).keys():
            yield Path(project)

    def _get_project_mcp_configurations(
        self, directory: Path
    ) -> Iterator[MCPConfiguration]:
        # Standard project-level MCP servers
        yield from super()._get_project_mcp_configurations(directory)
        # Detect local plugin
        yield from self._get_codex_plugin_mcp_configurations(directory, Scope.PROJECT)

    def _get_user_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        # Standard user-level MCP servers
        yield from super()._get_user_mcp_configurations()
        # Detect plugins
        # (arborescence is plugins/cache/<marketplace>/<plugin>/<hash>/)
        for plugin_dir in self.config_folder.glob("plugins/cache/*/*/*"):
            yield from self._get_codex_plugin_mcp_configurations(plugin_dir, Scope.USER)

    def _get_codex_plugin_mcp_configurations(
        self, plugin_dir: Path, scope: Scope
    ) -> Iterator[MCPConfiguration]:
        # Try to read the package.json
        if package := self._load_file(plugin_dir / ".codex-plugin" / "package.json"):
            display_name = package.get("interface", {}).get("displayName")
            mcp_location = package.get("mcpServers", ".mcp.json")
        else:
            display_name = None
            mcp_location = ".mcp.json"

        # Try to read the mcp.json file
        if not (data := self._load_file(plugin_dir / mcp_location)):
            return

        yield from self._parse_servers_block(
            data, scope, None if scope == Scope.USER else plugin_dir, display_name
        )

    def parse_mcp_activity(
        self, payload: HookPayload, ai_config: AIDiscovery
    ) -> MCPActivityRequest:
        raw_tool_name: str = payload.raw.get("tool_name", "")
        parts = raw_tool_name.split("__")
        tool = parts[-1]
        server_cfg_name = "__".join(parts[1:-1])

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
            model=payload.raw.get("model", ""),
            cwd=payload.raw.get("cwd", ""),
            input=payload.raw.get("tool_input", {}),
        )
