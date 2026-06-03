import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

import click

from ggshield.core.dirs import get_user_home_dir
from ggshield.verticals.ai.agent_activity.sources import JSONLActivitySource
from ggshield.verticals.ai.models import (
    AIDiscovery,
    EventType,
    HookPayload,
    HookResult,
    MCPActivityRequest,
    MCPConfiguration,
    Scope,
    Tool,
    Transport,
)

from .vscode import VSCode


logger = logging.getLogger(__name__)


class CopilotActivitySource(JSONLActivitySource):
    """Every Copilot CLI session line, shipped raw.

    Copilot CLI appends one JSON object per line to
    ~/.copilot/session-state/<uuid>/events.jsonl. The line is shipped
    verbatim; GitGuardian scans and strips secrets server-side before storing it.
    """

    kind = "session_events"

    def discover(self) -> Iterator[Path]:
        root = get_user_home_dir() / ".copilot"
        return iter(sorted(root.glob("session-state/*/events.jsonl")))


class Copilot(VSCode):
    """Behavior specific to Copilot CLI.

    Inherits most of its behavior from VSCode.
    """

    # Override VSCode's source: Copilot stores sessions under a different root.
    agent_activity_sources = [CopilotActivitySource()]

    @property
    def name(self) -> str:
        return "copilot"

    @property
    def display_name(self) -> str:
        return "Copilot CLI"

    @property
    def config_folder(self) -> Path:
        return get_user_home_dir() / ".copilot"

    def project_mcp_file(self, directory: Path) -> Path:
        return directory / ".mcp.json"

    @property
    def user_mcp_file(self) -> Path:
        return self.config_folder / "mcp-config.json"

    def _get_user_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        # Standard user-level MCP servers
        yield from super()._get_user_mcp_configurations()
        # Search in installed plugins
        for plugin_folder in self.config_folder.glob("installed-plugins/*/*/"):
            for config in self._get_project_mcp_configurations(plugin_folder):
                config.scope = Scope.USER
                config.project = None
                yield config
        # Hard-coded Github MCP server
        yield MCPConfiguration(
            name="github-mcp-server",
            agent=self.name,
            scope=Scope.USER,
            project=None,
            transport=Transport.HTTP,
            url="https://api.individual.githubcopilot.com/mcp/readonly",
        )

    def is_caller(self, hook_payload: dict[str, str]) -> bool:
        # Copilot CLI only emits the default fields in all hooks, which in a way identifies it.
        default_fields = {"hook_event_name", "session_id", "timestamp", "cwd"}
        optional_fields = {"prompt", "tool_name", "tool_input", "tool_result"}
        return set(hook_payload.keys()) - optional_fields == default_fields

    def output_result(self, result: HookResult) -> int:
        # Copilot CLI ignores the inherited `{"continue": false}` on the prompt
        # event, but it does honor `{"decision": "block"}` to cancel a prompt
        # before it reaches the model (verified against Copilot CLI 1.0.61).
        if result.block and result.payload.event_type == EventType.USER_PROMPT:
            click.echo(json.dumps({"decision": "block", "reason": result.message}))
            return 0
        return super().output_result(result)

    def post_process_payload(self, payload: HookPayload):
        # Copilot CLI doesn't prefix the MCP tools by any specific string,
        # so we need to identify them by elimination.
        if payload.tool == Tool.OTHER:
            tool_name = payload.raw.get("tool_name", "")
            # The list of tools provided in the official documentation is not exhaustive,
            # (they don't list "report_intent" for instance), so I have no confidence in having
            # a whitelist/blacklist. Instead, we rely on the fact that Copilot separates the server
            # and tool names by a "-", which is never used in other tool names (they are snake_cased).
            if "-" in tool_name:
                payload.tool = Tool.MCP

    def _lookup_server_name(
        self, raw_tool_name: str, ai_config: Optional[AIDiscovery]
    ) -> Tuple[str, str]:
        # Copilot's hook tool name is "{server}-{tool}"
        # which is unfortunate because server names can contain "-" in their name.
        # It also mangles the config name (replaces spaces, uses punycode encoding, ...).
        # It doesn't look like it can import MCP servers from other agents, so we filter them to avoid
        # false positives.
        # We look for the longest chain of parts separated by "-" that is a valid server configuration name.

        # Build a map of mangled server configuration names to server names.
        mangled_to_server: Dict[str, str] = (
            {
                _mangle_name(configuration.name): server.name
                for server in ai_config.servers
                for configuration in server.configurations
                if configuration.agent == self.name
            }
            if ai_config is not None
            else {}
        )

        parts = raw_tool_name.split("-")

        # At each separation point (starting from the biggest name possible), check if the mangled name is in the map.
        for i in range(len(parts)):
            # lower() because of IDNA encoding, whereas Copilot preserves the case.
            mangled_name = "-".join(parts[:-i]).lower()
            if mangled_name in mangled_to_server:
                return mangled_to_server[mangled_name], "-".join(parts[-i:])

        # If no match is found, fallback to use the last part as the tool name.
        return "-".join(parts[:-1]), parts[-1]

    def iter_history_events(
        self, ai_config: Optional[AIDiscovery]
    ) -> Iterator[MCPActivityRequest]:
        """Walk every Copilot CLI session and yield MCP tool calls.

        Sessions live under ``~/.copilot/session-state/<uuid>/events.jsonl``.
        """
        history_root = self.config_folder / "session-state"
        for session_dir in sorted(history_root.glob("*")):
            events_path = session_dir / "events.jsonl"
            if not events_path.is_file():
                continue
            yield from self._parse_events_file(events_path, ai_config)

    def _parse_events_file(
        self, path: Path, ai_config: Optional[AIDiscovery]
    ) -> Iterator[MCPActivityRequest]:
        """Yield MCP events from a single Copilot CLI events file."""
        cwd = ""
        for line in self._load_jsonl_file(path):
            if not isinstance(line, dict):
                continue
            event_type = line.get("type")
            data = line.get("data") or {}
            if event_type == "session.start":
                folder = (data.get("context") or {}).get("cwd")
                if isinstance(folder, str):
                    cwd = folder
                continue
            if event_type != "tool.execution_start":
                continue
            event = self._build_event(line, data, cwd, ai_config)
            if event is not None:
                yield event

    def _build_event(
        self,
        line: Dict[str, Any],
        data: Dict[str, Any],
        cwd: str,
        ai_config: Optional[AIDiscovery],
    ) -> Optional[MCPActivityRequest]:
        server_cfg_name = data.get("mcpServerName") or ""
        tool_name = data.get("mcpToolName") or ""
        if not server_cfg_name or not tool_name:
            return None
        timestamp = _parse_iso_timestamp(line.get("timestamp"))
        if timestamp is None:
            return None
        arguments = data.get("arguments")
        if not isinstance(arguments, dict):
            arguments = {}
        return MCPActivityRequest(
            user=self._user_or_default(ai_config),
            tool=tool_name,
            server=self._resolve_server_name(server_cfg_name, ai_config),
            agent=self.name,
            model="",
            cwd=cwd,
            input=arguments,
            timestamp=timestamp,
        )


def _parse_iso_timestamp(raw: Any) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp string, tolerating a trailing ``Z``."""
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _mangle_name(name: str) -> str:
    """Mangle a name in the same way Copilot does."""
    return re.sub(r"\W", "-", name.lower()).encode("idna").decode()
