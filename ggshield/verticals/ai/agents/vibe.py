import json
import os
from pathlib import Path
from typing import Any, Dict, Iterator, Literal, Optional, Tuple

import click
from pygitguardian.models import AIDiscovery, MCPActivityRequest

from ggshield.core.dirs import get_user_home_dir

from ..models import (
    Agent,
    HookPayload,
    HookResult,
    MCPConfiguration,
    Scope,
    Tool,
    Transport,
)


class Vibe(Agent):
    """Behavior specific to the Mistral Vibe CLI."""

    @property
    def name(self) -> str:
        return "vibe"

    @property
    def display_name(self) -> str:
        return "Mistral Vibe"

    @property
    def config_folder(self) -> Path:
        if custom_home := os.getenv("VIBE_HOME"):
            return Path(custom_home).expanduser()
        return get_user_home_dir() / ".vibe"

    def output_result(self, result: HookResult) -> int:
        response: Dict[str, Any] = {}
        if result.block:
            response["decision"] = "deny"
            response["reason"] = result.message
        elif result.warning:
            response["system_message"] = result.warning

        # Vibe's documented passthrough response is empty stdout.
        if response:
            click.echo(json.dumps(response))
        return 0

    def is_caller(self, hook_payload: Dict[str, Any]) -> bool:
        return hook_payload.get("hook_event_name") in {
            "pre_tool",
            "post_tool",
            "post_agent",
        }

    def settings_path(self, mode: Literal["local", "global"]) -> Path:
        if mode == "global":
            return self.config_folder / "hooks.toml"
        return Path(".vibe") / "hooks.toml"

    @property
    def settings_format(self) -> Literal["json", "toml"]:
        return "toml"

    def post_install_warning(self, mode: Literal["local", "global"]) -> Optional[str]:
        # Vibe only loads a project's .vibe/hooks.toml once the folder is
        # trusted, so a local install alone silently protects nothing.
        if mode == "global":
            return None
        cwd = Path.cwd().resolve()
        if any(cwd == trusted or trusted in cwd.parents for trusted in self._trusted()):
            return None
        return (
            f"{self.display_name} only loads project hooks from trusted folders. "
            f"Run 'vibe' once in {cwd} and accept the trust prompt, otherwise "
            "these hooks will be ignored."
        )

    def _trusted(self) -> Iterator[Path]:
        data = self._load_file(self.config_folder / "trusted_folders.toml") or {}
        for folder in data.get("trusted", []):
            if isinstance(folder, str):
                yield Path(folder).expanduser().resolve()

    @property
    def settings_template(self) -> Dict[str, Any]:
        command = "<COMMAND>"
        return {
            "hooks": [
                {
                    "name": "ggshield-pre-tool",
                    "type": "pre_tool",
                    "match": "*",
                    "command": command,
                    "strict": False,
                    "description": "Scan tool inputs for secrets before execution.",
                },
                {
                    "name": "ggshield-post-tool",
                    "type": "post_tool",
                    "match": "*",
                    "command": command,
                    "strict": False,
                    "description": "Scan tool outputs for secrets after execution.",
                },
            ]
        }

    def settings_locate(
        self, candidates: list[Dict[str, Any]], template: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        name = template.get("name")
        return next(
            (candidate for candidate in candidates if candidate.get("name") == name),
            None,
        )

    def project_mcp_file(self, directory: Path) -> Path:
        return directory / ".vibe" / "config.toml"

    @property
    def user_mcp_file(self) -> Path:
        return self.config_folder / "config.toml"

    def discover_project_directories(self) -> Iterator[Path]:
        for path in self._trusted():
            if path.is_dir():
                yield path

    def _get_user_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        data = self._load_file(self.user_mcp_file)
        if data:
            yield from self._parse_vibe_mcp_servers(data, Scope.USER, None)

    def _get_project_mcp_configurations(
        self, directory: Path
    ) -> Iterator[MCPConfiguration]:
        data = self._load_file(self.project_mcp_file(directory))
        if data:
            yield from self._parse_vibe_mcp_servers(data, Scope.PROJECT, directory)

    def _parse_vibe_mcp_servers(
        self, data: Dict[str, Any], scope: Scope, project: Optional[Path]
    ) -> Iterator[MCPConfiguration]:
        servers = data.get("mcp_servers", [])
        if not isinstance(servers, list):
            return
        for entry in servers:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                continue

            # Vibe has no SSE transport: stdio, http and streamable-http only.
            transport_name = entry.get("transport", "stdio")
            if transport_name in {"http", "streamable-http"} or "url" in entry:
                transport = Transport.HTTP
            else:
                transport = Transport.STDIO

            auth = entry.get("auth", {})
            auth_headers = auth.get("headers", {}) if isinstance(auth, dict) else {}
            headers = entry.get("headers", auth_headers)
            if not isinstance(headers, dict):
                headers = {}

            # Vibe accepts `command` as either a string or a full argv list.
            command = entry.get("command")
            args = entry.get("args", [])
            if isinstance(command, list):
                command, args = (command[0] if command else None), [
                    *command[1:],
                    *args,
                ]

            yield MCPConfiguration(
                name=entry["name"],
                agent=self.name,
                scope=scope,
                transport=transport,
                project=str(project) if project else None,
                command=command,
                args=args,
                env=entry.get("env", {}),
                url=entry.get("url"),
                headers=headers,
            )

    def post_process_payload(self, payload: HookPayload):
        if payload.tool not in {Tool.MCP, Tool.OTHER}:
            return
        raw_tool_name = payload.raw.get("tool_name", "")
        cwd = payload.raw.get("cwd", "")
        if self._match_mcp_tool_name(raw_tool_name, cwd) is not None:
            payload.tool = Tool.MCP
        else:
            # Vibe MCP tools use "{server}_{tool}", not an "mcp" prefix.
            # Undo the generic prefix heuristic unless a configured server
            # actually matches, so custom tools named "mcp_*" are not
            # misreported as MCP activity.
            payload.tool = Tool.OTHER

    def _match_mcp_tool_name(
        self, raw_tool_name: str, cwd: str
    ) -> Optional[Tuple[str, str]]:
        configurations = list(self._get_user_mcp_configurations())
        if cwd:
            configurations.extend(self._get_project_mcp_configurations(Path(cwd)))
        names = sorted(
            {configuration.name for configuration in configurations},
            key=len,
            reverse=True,
        )
        for name in names:
            prefix = f"{name}_"
            if raw_tool_name.startswith(prefix):
                return name, raw_tool_name.removeprefix(prefix)
        return None

    def parse_mcp_activity(
        self, payload: HookPayload, ai_config: AIDiscovery
    ) -> MCPActivityRequest:
        raw_tool_name = payload.raw.get("tool_name", "")
        configuration_name = ""
        tool_name = raw_tool_name
        server_name = ""

        candidates = []
        for server in ai_config.servers:
            for configuration in server.configurations:
                if configuration.agent != self.name:
                    continue
                prefix = f"{configuration.name}_"
                if raw_tool_name.startswith(prefix):
                    candidates.append(
                        (len(configuration.name), configuration.name, server.name)
                    )
        if candidates:
            _, configuration_name, server_name = max(candidates)
            tool_name = raw_tool_name.removeprefix(f"{configuration_name}_")
        elif matched := self._match_mcp_tool_name(
            raw_tool_name, payload.raw.get("cwd", "")
        ):
            configuration_name, tool_name = matched
            server_name = configuration_name

        return MCPActivityRequest(
            user=ai_config.user,
            tool=tool_name,
            server=server_name or configuration_name,
            agent=self.name,
            model="",
            cwd=payload.raw.get("cwd", ""),
            input=payload.raw.get("tool_input", {}),
            timestamp=payload.timestamp,
        )
