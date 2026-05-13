import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Literal, Optional

import click
from pygitguardian.models import AIDiscovery, MCPActivityRequest

from ggshield.core.dirs import get_user_home_dir

from ..models import Agent, EventType, HookPayload, HookResult
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

    def settings_path(self, mode: Literal["local", "global"]) -> Path:
        return Path(".codex") / "hooks.json"

    @property
    def settings_template(self) -> Dict[str, Any]:
        return {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": ".*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "<COMMAND>",
                            }
                        ],
                    }
                ],
                "PostToolUse": [
                    {
                        "matcher": ".*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "<COMMAND>",
                            }
                        ],
                    }
                ],
                "UserPromptSubmit": [
                    {
                        "hooks": [
                            {
                                "type": "command",
                                "command": "<COMMAND>",
                            }
                        ],
                    }
                ],
            }
        }

    def settings_locate(
        self, candidates: List[Dict[str, Any]], template: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        if "matcher" in template:
            for obj in candidates:
                if obj.get("matcher") == template["matcher"]:
                    return obj
            return None
        for obj in candidates:
            command = obj.get("command", "")
            if "ggshield" in command or "<COMMAND>" in command:
                return obj
        for obj in candidates:
            for hook in obj.get("hooks", []):
                command = hook.get("command", "")
                if "ggshield" in command or "<COMMAND>" in command:
                    return obj
        return None

    def project_mcp_file(self, directory: Path) -> Path:
        return directory / ".codex" / "config.toml"

    def discover_project_directories(self) -> Iterator[Path]:
        yield from []

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
