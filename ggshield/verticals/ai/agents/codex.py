import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, Literal, Optional

import click
from pygitguardian.models import AIDiscovery, MCPActivityRequest

from ggshield.core.dirs import get_user_home_dir

from ..agent_activity.sources import JSONLActivitySource
from ..models import Agent, EventType, HookPayload, HookResult, MCPConfiguration, Scope
from .claude_code import _mangle_server_name


class CodexActivitySource(JSONLActivitySource):
    """Every Codex session rollout line, shipped raw.

    Codex writes one response_item / metadata object per line to
    ~/.codex/sessions/<YYYY>/<MM>/<DD>/rollout-*.jsonl. The line is shipped
    verbatim; GitGuardian scans and strips secrets server-side before storing it.
    """

    kind = "session_rollout"

    def discover(self) -> Iterator[Path]:
        return iter(
            sorted(
                (get_user_home_dir() / ".codex").glob("sessions/*/*/*/rollout-*.jsonl")
            )
        )


class Codex(Agent):
    """Behavior specific to OpenAI Codex."""

    agent_activity_sources = [CodexActivitySource()]

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

        return MCPActivityRequest(
            user=ai_config.user,
            tool=tool,
            server=self._resolve_server_name(server_cfg_name, ai_config),
            agent=self.name,
            model=payload.raw.get("model", ""),
            cwd=payload.raw.get("cwd", ""),
            input=payload.raw.get("tool_input", {}),
            timestamp=payload.timestamp,
        )

    def iter_history_events(
        self, ai_config: Optional[AIDiscovery]
    ) -> Iterator[MCPActivityRequest]:
        """Walk every Codex session rollout and yield its MCP tool_use events."""
        for path in self._history_files():
            yield from self._parse_session_file(path, ai_config)

    def _history_files(self) -> Iterator[Path]:
        """Yield every Codex session rollout file we know about."""
        yield from sorted(self.config_folder.glob("sessions/*/*/*/rollout-*.jsonl"))

    def _parse_session_file(
        self, path: Path, ai_config: Optional[AIDiscovery]
    ) -> Iterator[MCPActivityRequest]:
        """Yield MCPActivityRequest events from a single Codex session rollout."""
        cwd = ""
        model = ""
        for entry in self._load_jsonl_file(path):
            if not isinstance(entry, dict):
                continue
            payload = entry.get("payload")
            if not isinstance(payload, dict):
                continue
            entry_type = entry.get("type")
            if entry_type == "session_meta":
                cwd = payload.get("cwd") or cwd
                continue
            if entry_type == "turn_context":
                cwd = payload.get("cwd") or cwd
                model = payload.get("model") or model
                continue
            if entry_type != "response_item":
                continue
            if payload.get("type") != "function_call":
                continue
            namespace = payload.get("namespace") or ""
            if not namespace.startswith("mcp__"):
                continue
            event = self._build_activity_from_function_call(
                entry, payload, namespace, cwd, model, ai_config
            )
            if event is not None:
                yield event

    def _build_activity_from_function_call(
        self,
        entry: Dict[str, Any],
        payload: Dict[str, Any],
        namespace: str,
        cwd: str,
        model: str,
        ai_config: Optional[AIDiscovery],
    ) -> Optional[MCPActivityRequest]:
        """Turn one function_call response_item into an MCPActivityRequest."""
        tool = payload.get("name") or ""
        if not tool:
            return None
        server_cfg_name = namespace.removeprefix("mcp__").removesuffix("__")
        try:
            tool_input = json.loads(payload.get("arguments") or "{}")
        except (json.JSONDecodeError, TypeError):
            tool_input = {}
        if not isinstance(tool_input, dict):
            tool_input = {}
        try:
            ts = datetime.fromisoformat(
                str(entry.get("timestamp", "")).replace("Z", "+00:00")
            )
        except ValueError:
            return None
        return MCPActivityRequest(
            user=self._user_or_default(ai_config),
            tool=tool,
            server=self._resolve_server_name(server_cfg_name, ai_config),
            agent=self.name,
            model=model,
            cwd=cwd,
            input=tool_input,
            timestamp=ts,
        )

    def _resolve_server_name(
        self, cfg_name: str, ai_config: Optional[AIDiscovery]
    ) -> str:
        """Look up the canonical server name; fall back to the configuration name."""
        if ai_config is None:
            return cfg_name
        for server in ai_config.servers:
            for configuration in server.configurations:
                if _mangle_server_name(configuration.name) == cfg_name:
                    return server.name
        return cfg_name
