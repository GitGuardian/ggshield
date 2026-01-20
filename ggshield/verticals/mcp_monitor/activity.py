"""
MCP Activity Monitor - Logs all MCP tool executions with server identification.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ggshield.verticals.mcp_monitor.config import (
    extract_host_from_config,
    get_mcp_cache_dir,
    get_mcp_output_dir,
    load_json_file,
    load_mcp_config,
    save_json_file,
)
from ggshield.verticals.mcp_monitor.identity import MCPIdentityMapper


@dataclass
class MCPActivityEntry:
    timestamp: str
    service: Optional[str]
    host: Optional[str]
    cursor_email: Optional[str]
    tool: str
    identity: Optional[Dict[str, Any]]
    scopes: Optional[str]


def create_activity_entry(
    server_name: Optional[str],
    server_config: Optional[Dict[str, Any]],
    tool_name: str,
    user_email: Optional[str],
    scopes_mapping: Dict[str, str],
) -> MCPActivityEntry:
    identity = None
    if server_name and server_config:
        identity_mapper = MCPIdentityMapper()
        identity = identity_mapper.get_identity(server_name, server_config)

    return MCPActivityEntry(
        timestamp=datetime.now().isoformat(),
        service=server_name,
        host=extract_host_from_config(server_config),
        cursor_email=user_email,
        tool=tool_name,
        identity=identity,
        scopes=scopes_mapping.get(server_name) if server_name else None,
    )


@dataclass
class MCPActivityMonitor:
    workspace_roots: List[str] = field(default_factory=list)
    _mcp_config: Optional[Dict[str, Any]] = field(default=None, init=False)
    _tool_mapping: Optional[Dict[str, str]] = field(default=None, init=False)
    _scopes_mapping: Optional[Dict[str, str]] = field(default=None, init=False)

    @property
    def cache_dir(self) -> Path:
        return get_mcp_cache_dir()

    @property
    def output_dir(self) -> Path:
        return get_mcp_output_dir()

    @property
    def server_cache_path(self) -> Path:
        return self.cache_dir / "mcp_server_cache.json"

    @property
    def tool_mapping_path(self) -> Path:
        return self.cache_dir / "mcp_tool_mapping.json"

    @property
    def scopes_mapping_path(self) -> Path:
        return self.cache_dir / "mcp_scopes_mapping.json"

    @property
    def log_debug_path(self) -> Path:
        return self.output_dir / "mcp_monitor_debug.json"

    @property
    def log_info_path(self) -> Path:
        return self.output_dir / "mcp_monitor_info.json"

    @property
    def mcp_config(self) -> Dict[str, Any]:
        if self._mcp_config is None:
            self._mcp_config = load_mcp_config(self.workspace_roots)
        return self._mcp_config

    @property
    def tool_mapping(self) -> Dict[str, str]:
        if self._tool_mapping is None:
            if self.tool_mapping_path.exists():
                mapping = load_json_file(self.tool_mapping_path)
                self._tool_mapping = mapping if isinstance(mapping, dict) else {}
            else:
                from ggshield.verticals.mcp_monitor.tool_mapping import (
                    MCPToolMappingBuilder,
                )

                builder = MCPToolMappingBuilder(workspace_roots=self.workspace_roots)
                self._tool_mapping = builder.save_mapping()
        return self._tool_mapping

    @property
    def scopes_mapping(self) -> Dict[str, str]:
        if self._scopes_mapping is None:
            mapping = load_json_file(self.scopes_mapping_path)
            self._scopes_mapping = mapping if isinstance(mapping, dict) else {}
        return self._scopes_mapping

    def find_server_by_command(
        self, command: str
    ) -> tuple[Optional[str], Optional[Dict[str, Any]]]:
        if not command:
            return None, None
        for server_name, server_data in self.mcp_config.get("mcpServers", {}).items():
            server_command = server_data.get("command", "")
            server_args = server_data.get("args", [])
            full_command = " ".join([server_command] + server_args)
            if full_command == command or server_command == command:
                return server_name, server_data
        return None, None

    def find_server_by_tool_mapping(
        self, tool_name: str
    ) -> tuple[Optional[str], Optional[Dict[str, Any]]]:
        if not tool_name:
            return None, None

        server_name = self.tool_mapping.get(tool_name)
        if server_name:
            server_config = self.mcp_config.get("mcpServers", {}).get(server_name)
            if server_config:
                return server_name, server_config

        return None, None

    def learn_tool_mapping(self, tool_name: str, server_name: str) -> None:
        if not tool_name or not server_name:
            return

        if self.tool_mapping.get(tool_name) != server_name:
            self._tool_mapping = dict(self.tool_mapping)
            self._tool_mapping[tool_name] = server_name
            save_json_file(self.tool_mapping_path, self._tool_mapping)

    def get_cache_key(self, data: Dict[str, Any]) -> str:
        return f"{data.get('generation_id', '')}:{data.get('tool_name', '')}"

    def get_cached_server_info(
        self, cache_key: str
    ) -> tuple[Optional[str], Optional[Dict[str, Any]]]:
        cache = load_json_file(self.server_cache_path)
        if not isinstance(cache, dict):
            return None, None
        entry = cache.get(cache_key, {})
        return entry.get("server_name"), entry.get("server_config")

    def cache_server_info(
        self,
        cache_key: str,
        server_name: Optional[str],
        server_config: Optional[Dict[str, Any]],
    ) -> None:
        if not server_name:
            return
        cache = load_json_file(self.server_cache_path)
        if not isinstance(cache, dict):
            cache = {}
        cache[cache_key] = {"server_name": server_name, "server_config": server_config}
        save_json_file(self.server_cache_path, cache)

    def identify_server(
        self, event_data: Dict[str, Any]
    ) -> tuple[Optional[str], Optional[Dict[str, Any]]]:
        command = event_data.get("command", "")
        tool_name = event_data.get("tool_name", "")
        event_type = event_data.get("hook_event_name", "")
        cache_key = self.get_cache_key(event_data)

        server_name, server_config = self.find_server_by_command(command)

        if not server_name:
            server_name, server_config = self.find_server_by_tool_mapping(tool_name)

        if not server_name and event_type == "afterMCPExecution":
            server_name, server_config = self.get_cached_server_info(cache_key)

        if server_name and event_type == "beforeMCPExecution":
            self.cache_server_info(cache_key, server_name, server_config)
            self.learn_tool_mapping(tool_name, server_name)

        return server_name, server_config

    def log_activity(
        self,
        event_data: Dict[str, Any],
        server_name: Optional[str],
        server_config: Optional[Dict[str, Any]],
    ) -> None:
        event_type = event_data.get("hook_event_name", "")

        if event_type == "afterMCPExecution":
            return

        self._parse_json_field(event_data, "tool_input")

        debug_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "mcp_server_name": server_name,
            "mcp_server_config": server_config,
            "hook_input": event_data,
        }

        debug_entries = (
            load_json_file(self.log_debug_path) if self.log_debug_path.exists() else []
        )
        if not isinstance(debug_entries, list):
            debug_entries = []
        debug_entries.append(debug_entry)
        save_json_file(self.log_debug_path, debug_entries)

        tool_name = event_data.get("tool_name", "")
        entry = create_activity_entry(
            server_name=server_name,
            server_config=server_config,
            tool_name=tool_name,
            user_email=event_data.get("user_email"),
            scopes_mapping=self.scopes_mapping,
        )

        info_entries = (
            load_json_file(self.log_info_path) if self.log_info_path.exists() else []
        )
        if not isinstance(info_entries, list):
            info_entries = []
        info_entries.append(
            {
                "timestamp": entry.timestamp,
                "service": entry.service,
                "host": entry.host,
                "cursor_email": entry.cursor_email,
                "tool": entry.tool,
                "identity": entry.identity,
                "scopes": entry.scopes,
            }
        )
        save_json_file(self.log_info_path, info_entries)

    def _parse_json_field(self, data: Dict[str, Any], field: str) -> None:
        if field in data and isinstance(data[field], str):
            try:
                data[field] = json.loads(data[field])
            except json.JSONDecodeError:
                pass

    def process_event(self, event_data: Dict[str, Any]) -> Dict[str, str]:
        server_name, server_config = self.identify_server(event_data)
        self.log_activity(event_data, server_name, server_config)
        return {"decision": "allow"}
