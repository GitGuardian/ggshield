import json
import re
from pathlib import Path
from typing import Any, Dict, Iterator, Literal, Tuple

import click
from pygitguardian.models import AIDiscovery, MCPActivityRequest

from ggshield.core.dirs import get_user_home_dir

from ..models import Agent, EventType, HookPayload, HookResult


class VSCode(Agent):
    """Behavior specific to VSCode."""

    @property
    def name(self) -> str:
        return "vscode"

    @property
    def display_name(self) -> str:
        return "VSCode"

    @property
    def config_folder(self) -> Path:
        return get_user_home_dir() / ".config" / "Code" / "User"

    def output_result(self, result: HookResult) -> int:
        response = {}
        if result.block:
            if result.payload.event_type == EventType.PRE_TOOL_USE:
                response["hookSpecificOutput"] = {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": result.message,
                }
            elif result.payload.event_type == EventType.POST_TOOL_USE:
                response["decision"] = "block"
                response["reason"] = result.message
            else:
                response["continue"] = False
                response["stopReason"] = result.message
        else:
            response["continue"] = True

        click.echo(json.dumps(response))
        return 0

    def is_caller(self, hook_payload: Dict[str, Any]) -> bool:
        return "github.copilot-chat" in hook_payload.get("transcript_path", "").lower()

    def settings_path(self, mode: Literal["local", "global"]) -> Path:
        return (
            Path(".github" if mode == "local" else ".copilot") / "hooks" / "hooks.json"
        )

    def project_mcp_file(self, directory: Path) -> Path:
        return directory / ".vscode" / "mcp.json"

    def discover_project_directories(self) -> Iterator[Path]:
        # Try to parse workspaces settings.
        for file in self.config_folder.glob("workspaceStorage/*/workspace.json"):
            if (data := self._load_json_file(file)) and "folder" in data:
                path = Path(data["folder"].removeprefix("file://"))
                if path.is_dir():
                    yield path.resolve()

    def parse_mcp_activity(
        self, payload: HookPayload, ai_config: AIDiscovery
    ) -> MCPActivityRequest:
        """Parse the MCP activity from an MCP hook payload."""

        raw_tool_name: str = payload.raw.get("tool_name", "")
        server_name, tool_name = self._lookup_server_name(raw_tool_name, ai_config)

        return MCPActivityRequest(
            user=ai_config.user,
            tool=tool_name,
            server=server_name,
            agent=self.name,
            model="",
            cwd=payload.raw.get("cwd", ""),
            input=payload.raw.get("tool_input", {}),
        )

    def _lookup_server_name(
        self, raw_tool_name: str, ai_config: AIDiscovery
    ) -> Tuple[str, str]:
        # VSCode's hook tool name is "mcp_{server}_{tool}"
        # which is unfortunate because a lot of tools have a "_" in their name.
        # It also mangles the config name (lowercase, groups of non-alphanumeric
        # characters are replaced by a single "_", and only the first 13 characters are kept).
        # We may not have the list of tools available and VSCode can use MCP servers
        # from other agents (like Claude Code), so for now as a best effort attempt,
        # we look for the longest chain of parts separated by "_" that is a valid server configuration name.

        # Build a map of mangled server configuration names to server names.
        mangled_to_server: Dict[str, str] = {
            _mangle_name(configuration.name): server.name
            for server in ai_config.servers
            for configuration in server.configurations
        }

        # This get rid of the "mcp_" prefix.
        _, *parts = raw_tool_name.split("_")

        # At each separation point (starting from the biggest name possible), check if the mangled name is in the map.
        for i in range(len(parts)):
            mangled_name = "_".join(parts[:-i])
            if mangled_name in mangled_to_server:
                return mangled_to_server[mangled_name], "_".join(parts[-i:])

        # If no match is found, fallback to use the first part as the server name.
        return parts[0], "_".join(parts[1:])


MANGLING_PATTERN = re.compile(r"[^A-Za-z0-9-]+")


def _mangle_name(name: str) -> str:
    """Mangle a name in the same way VSCode does."""
    return MANGLING_PATTERN.sub("_", name).lower()[:13]
