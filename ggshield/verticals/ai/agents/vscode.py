import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Literal, Optional, Tuple

import click
from pygitguardian.models import AIDiscovery, MCPActivityRequest

from ggshield.core.dirs import get_editor_user_data_dir, get_user_home_dir

from ..agent_activity.sources import JSONLActivitySource
from ..models import Agent, EventType, HookPayload, HookResult, MCPConfiguration


logger = logging.getLogger(__name__)


class VSCodeActivitySource(JSONLActivitySource):
    """Base class for VSCode activity sources."""

    @staticmethod
    def _user_dir() -> Path:
        return get_editor_user_data_dir("Code")

    def source_path_for(self, path: Path, path_root: Optional[Path]) -> str:
        # Record paths relative to the editor's User dir (not the agent's
        # config_folder), so the shipped path is the same on every OS.
        return super().source_path_for(path, self._user_dir())


class VSCodeChatSessionsActivitySource(VSCodeActivitySource):
    kind = "5_chat_session"

    def discover(self) -> Iterator[Path]:
        root = self._user_dir()
        return iter(sorted(root.glob("workspaceStorage/*/chatSessions/*.jsonl")))


class VSCodeTranscriptsActivitySource(VSCodeActivitySource):
    kind = "6_transcript"

    def discover(self) -> Iterator[Path]:
        root = self._user_dir()
        return iter(
            sorted(
                root.glob("workspaceStorage/*/GitHub.copilot-chat/transcripts/*.jsonl")
            )
        )


class VSCode(Agent):
    """Behavior specific to VSCode."""

    agent_activity_sources = [
        VSCodeChatSessionsActivitySource(),
        VSCodeTranscriptsActivitySource(),
    ]

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
            if result.warning:
                response["systemMessage"] = result.warning

        click.echo(json.dumps(response))
        return 0

    def is_caller(self, hook_payload: Dict[str, Any]) -> bool:
        return (
            "github.copilot-chat" in (hook_payload.get("transcript_path") or "").lower()
        )

    def settings_path(self, mode: Literal["local", "global"]) -> Path:
        return (
            Path(".github" if mode == "local" else ".copilot") / "hooks" / "hooks.json"
        )

    def project_mcp_file(self, directory: Path) -> Path:
        return directory / ".vscode" / "mcp.json"

    @property
    def user_mcp_file(self) -> Path:
        return self.config_folder / "mcp.json"

    def discover_project_directories(self) -> Iterator[Path]:
        # Try to parse workspaces settings.
        for file in self.config_folder.glob("workspaceStorage/*/workspace.json"):
            if (data := self._load_file(file)) and "folder" in data:
                path = Path(data["folder"].removeprefix("file://"))
                if path.is_dir():
                    yield path.resolve()

    def _get_user_mcp_configurations(self) -> Iterator[MCPConfiguration]:
        confs = list(super()._get_user_mcp_configurations())
        # We can find display names in the extensions MCP configurations,
        # update the configurations accordingly
        display_names = self._get_extensions_names()
        for config in confs:
            if config.name in display_names:
                config.display_name = display_names[config.name]
        return iter(confs)

    def _get_extensions_names(self) -> Dict[str, str]:
        """Get the display names of the MCP servers installed from the VS Code MCP gallery."""
        names: Dict[str, str] = {}
        for file in self.config_folder.glob("mcp/*/manifest.json"):
            if not (data := self._load_file(file)):
                continue
            name = data.get("name", "")
            display_name = data.get("displayName")
            if display_name:
                names[name] = display_name
        return names

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
            timestamp=payload.timestamp,
        )

    def _lookup_server_name(
        self, raw_tool_name: str, ai_config: Optional[AIDiscovery]
    ) -> Tuple[str, str]:
        # VSCode's hook tool name is "mcp_{server}_{tool}"
        # which is unfortunate because a lot of tools have a "_" in their name.
        # It also mangles the config name (lowercase, groups of non-alphanumeric
        # characters are replaced by a single "_", and only the first 13 characters are kept).
        # We may not have the list of tools available and VSCode can use MCP servers
        # from other agents (like Claude Code), so for now as a best effort attempt,
        # we look for the longest chain of parts separated by "_" that is a valid server configuration name.

        # Build a map of mangled server configuration names to server names.
        mangled_to_server: Dict[str, str] = (
            {
                _mangle_name(configuration.name): server.name
                for server in ai_config.servers
                for configuration in server.configurations
            }
            if ai_config is not None
            else {}
        )

        # This get rid of the "mcp_" prefix.
        _, *parts = raw_tool_name.split("_")

        # At each separation point (starting from the biggest name possible), check if the mangled name is in the map.
        for i in range(len(parts)):
            mangled_name = "_".join(parts[:-i])
            if mangled_name in mangled_to_server:
                return mangled_to_server[mangled_name], "_".join(parts[-i:])

        # If no match is found, fallback to use the first part as the server name.
        return parts[0], "_".join(parts[1:])

    def iter_history_events(
        self, ai_config: Optional[AIDiscovery]
    ) -> Iterator[MCPActivityRequest]:
        """Walk every Copilot Chat session and yield MCP tool calls.

        Sessions live under
        ``/workspaceStorage/<hash>/chatSessions/<id>.jsonl``.
        Iterating per-workspace lets us read each ``workspace.json`` once.
        """
        for workspace_dir in sorted(self.config_folder.glob("workspaceStorage/*")):
            cwd = self._workspace_cwd(workspace_dir)
            for session in sorted(workspace_dir.glob("chatSessions/*.jsonl")):
                try:
                    yield from self._parse_session_file(session, cwd, ai_config)
                except OSError as exc:
                    logger.warning("VSCode: skipping %s: %s", session, exc)

    def _workspace_cwd(self, workspace_dir: Path) -> str:
        """Return the project folder backing a ``workspaceStorage/<hash>`` directory."""
        data = self._load_file(workspace_dir / "workspace.json")
        folder = (data or {}).get("folder", "") if data else ""
        return folder.removeprefix("file://") if isinstance(folder, str) else ""

    def _parse_session_file(
        self, path: Path, cwd: str, ai_config: Optional[AIDiscovery]
    ) -> Iterator[MCPActivityRequest]:
        """Yield deduped MCP events from a single Copilot Chat session file."""
        seen: set = set()
        last_ts: Optional[datetime] = None
        with path.open("r", encoding="utf-8", errors="ignore") as history_file:
            for raw in history_file:
                try:
                    line = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    continue
                content = line.get("v") if isinstance(line, dict) else None
                # toolInvocation lines have no timestamp, try finding one around them
                line_max = max(_iter_timestamps(content), default=None)
                if line_max is not None:
                    try:
                        candidate = datetime.fromtimestamp(
                            line_max / 1000, tz=timezone.utc
                        )
                    except (ValueError, OSError, OverflowError):
                        candidate = None
                    if candidate is not None and (
                        last_ts is None or candidate > last_ts
                    ):
                        last_ts = candidate
                for inv in _find_mcp_invocations(content):
                    tool_call_id = inv.get("toolCallId")
                    if not tool_call_id or tool_call_id in seen:
                        continue
                    event = self._build_activity(inv, cwd, last_ts, ai_config)
                    if event is None:
                        continue
                    seen.add(tool_call_id)
                    yield event

    def _build_activity(
        self,
        invocation: Dict[str, Any],
        cwd: str,
        timestamp: Optional[datetime],
        ai_config: Optional[AIDiscovery],
    ) -> Optional[MCPActivityRequest]:
        if timestamp is None:
            return None
        source = invocation.get("source") or {}
        server_cfg_name = source.get("label") or ""
        tool_id = invocation.get("toolId") or ""
        if not server_cfg_name or not tool_id:
            return None
        tool_input = (invocation.get("toolSpecificData") or {}).get("rawInput") or {}
        if not isinstance(tool_input, dict):
            tool_input = {}
        _, tool_name = self._lookup_server_name(tool_id, ai_config)
        return MCPActivityRequest(
            user=self._user_or_default(ai_config),
            tool=tool_name,
            server=self._resolve_server_name(server_cfg_name, ai_config),
            agent=self.name,
            model="",
            cwd=cwd,
            input=tool_input,
            timestamp=timestamp,
        )

    def _resolve_server_name(
        self, cfg_name: str, ai_config: Optional[AIDiscovery]
    ) -> str:
        """Resolve a bubble's ``source.label`` to the canonical server name."""
        if ai_config is None or not cfg_name:
            return cfg_name
        for server in ai_config.servers:
            for configuration in server.configurations:
                if configuration.name == cfg_name:
                    return server.name
        return cfg_name


def _iter_timestamps(obj: Any) -> Iterator[int]:
    """Yield every numeric ``timestamp`` (unix ms) nested anywhere in ``obj``."""
    if isinstance(obj, dict):
        ts = obj.get("timestamp")
        if isinstance(ts, (int, float)) and not isinstance(ts, bool):
            yield int(ts)
        for value in obj.values():
            yield from _iter_timestamps(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _iter_timestamps(value)


def _find_mcp_invocations(obj: Any) -> Iterator[Dict[str, Any]]:
    """Yield every ``toolInvocationSerialized`` dict with ``source.type == "mcp"``."""
    if isinstance(obj, dict):
        if obj.get("kind") == "toolInvocationSerialized":
            source = obj.get("source") or {}
            if isinstance(source, dict) and source.get("type") == "mcp":
                yield obj
        for value in obj.values():
            yield from _find_mcp_invocations(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _find_mcp_invocations(value)


MANGLING_PATTERN = re.compile(r"[^A-Za-z0-9-]+")


def _mangle_name(name: str) -> str:
    """Mangle a name in the same way VSCode does."""
    return MANGLING_PATTERN.sub("_", name).lower()[:13]
