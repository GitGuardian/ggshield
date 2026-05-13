import json
from pathlib import Path
from typing import Any, Dict, Iterator, Literal, Tuple

import click
from pygitguardian.models import AIDiscovery, MCPActivityRequest

from ggshield.core.dirs import get_user_home_dir

from ..models import Agent, EventType, HookPayload, HookResult, MCPConfiguration


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

    def _get_user_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        yield from Agent._get_user_mcp_configurations(self)

    def parse_mcp_activity(
        self, payload: HookPayload, ai_config: AIDiscovery
    ) -> MCPActivityRequest:
        """Parse the MCP activity from an MCP hook payload."""

        raw_tool_name: str = payload.raw.get("tool_name", "")
        server_name, tool_name = _lookup_server_name(raw_tool_name, ai_config)

        return MCPActivityRequest(
            user=ai_config.user,
            tool=tool_name,
            server=server_name,
            agent=self.name,
            model="",
            cwd=payload.raw.get("cwd", ""),
            input=payload.raw.get("tool_input", {}),
        )


def _lookup_server_name(raw_tool_name: str, ai_config: AIDiscovery) -> Tuple[str, str]:
    # Copilot's hook tool name is "mcp_{server}_{tool}"
    # which is unfortunate because a lot of tools have a "_" in their name.
    # For now we hope there won't be "_" in the server configuration name
    # (this is less likely than in the tool name but very brittle).
    # TODO: test this more thoroughly and implement a better lookup.
    _, server_cfg_name, *tool_parts = raw_tool_name.split("_")
    tool = "_".join(tool_parts)

    # Lookup the server name based on its configuration name
    # Fallback to the configuration name if not found
    for server in ai_config.servers:
        for configuration in server.configurations:
            if configuration.name == server_cfg_name:
                return server.name, tool
    return server_cfg_name, tool
