"""
MCP Activity Monitor - Logs all MCP tool executions with server identification.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ggshield.core.client import create_session
from ggshield.core.config import Config
from ggshield.core.url_utils import urljoin
from ggshield.verticals.mcp_monitor.config import (
    extract_host_from_config,
    get_mcp_cache_dir,
    get_mcp_output_dir,
    load_json_file,
    load_mcp_config,
    save_json_file,
)
from ggshield.verticals.mcp_monitor.discovery import (
    compute_identity_repr,
    get_server_info_for_tool,
    load_discovery_cache,
    parse_scopes_to_list,
)
from ggshield.verticals.mcp_monitor.identity import MCPIdentityMapper

logger = logging.getLogger(__name__)


@dataclass
class MCPActivityEntry:
    timestamp: str
    service: Optional[str]
    host: Optional[str]
    cursor_email: Optional[str]
    tool: str
    identity: Optional[Dict[str, Any]]
    identity_repr: Optional[str]
    scopes: Optional[List[str]]


def create_activity_entry(
    server_name: Optional[str],
    server_config: Optional[Dict[str, Any]],
    tool_name: str,
    user_email: Optional[str],
    scopes_mapping: Dict[str, str],
) -> MCPActivityEntry:
    identity = None
    identity_repr = None
    scopes: Optional[List[str]] = None
    host = extract_host_from_config(server_config)

    cached_server = get_server_info_for_tool(tool_name)
    if cached_server:
        server_name = server_name or cached_server.name
        identity = cached_server.identity
        identity_repr = cached_server.identity_repr
        scopes = cached_server.scopes
        if not host and cached_server.env_vars:
            host = cached_server.env_vars.get(
                "CLICKHOUSE_HOST"
            ) or cached_server.env_vars.get("GITLAB_API_URL")
    elif server_name and server_config:
        identity_mapper = MCPIdentityMapper()
        identity, fetched_scopes = identity_mapper.get_identity_and_scopes(
            server_name, server_config
        )
        if fetched_scopes:
            scopes = parse_scopes_to_list(fetched_scopes)
        identity_repr = compute_identity_repr(server_name, identity)
    elif server_name:
        scopes_str = scopes_mapping.get(server_name)
        if scopes_str:
            scopes = parse_scopes_to_list(scopes_str)

    return MCPActivityEntry(
        timestamp=datetime.now().isoformat(),
        service=server_name,
        host=host,
        cursor_email=user_email,
        tool=tool_name,
        identity=identity,
        identity_repr=identity_repr,
        scopes=scopes,
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
            if self.scopes_mapping_path.exists():
                mapping = load_json_file(self.scopes_mapping_path)
                self._scopes_mapping = mapping if isinstance(mapping, dict) else {}
            else:
                identity_mapper = MCPIdentityMapper(
                    workspace_roots=self.workspace_roots
                )
                _, self._scopes_mapping = identity_mapper.build_mappings()
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

        discovery_cache = load_discovery_cache()
        if discovery_cache:
            server_name = discovery_cache.get("tool_to_server", {}).get(tool_name)
            if server_name:
                server_config = self.mcp_config.get("mcpServers", {}).get(server_name)
                if server_config:
                    return server_name, server_config

        server_name = self.tool_mapping.get(tool_name)
        if server_name:
            server_config = self.mcp_config.get("mcpServers", {}).get(server_name)
            if server_config:
                return server_name, server_config

        return None, None

    def _is_remote_server(self, server_name: str) -> bool:
        from ggshield.verticals.mcp_monitor.config import get_mcp_remote_url

        server_config = self.mcp_config.get("mcpServers", {}).get(server_name, {})
        return get_mcp_remote_url(server_config) is not None

    def learn_tool_mapping(self, tool_name: str, server_name: str) -> None:
        if not tool_name or not server_name:
            return

        existing_server = self.tool_mapping.get(tool_name)
        if existing_server == server_name:
            return

        if existing_server:
            existing_is_remote = self._is_remote_server(existing_server)
            new_is_remote = self._is_remote_server(server_name)
            if not existing_is_remote and new_is_remote:
                return

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
    ) -> Dict[str, Any]:
        event_type = event_data.get("hook_event_name", "")

        if event_type == "afterMCPExecution":
            return {"decision": "allow"}

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
        entry_dict = {
            "timestamp": entry.timestamp,
            "service": entry.service,
            "host": entry.host,
            "cursor_email": entry.cursor_email,
            "tool": entry.tool,
            "identity": entry.identity,
            "identity_repr": entry.identity_repr,
            "scopes": entry.scopes,
        }
        info_entries.append(entry_dict)
        save_json_file(self.log_info_path, info_entries)

        return self._send_to_api(entry_dict)

    def _parse_json_field(self, data: Dict[str, Any], field: str) -> None:
        if field in data and isinstance(data[field], str):
            try:
                data[field] = json.loads(data[field])
            except json.JSONDecodeError:
                pass

    def _send_to_api(self, entry_dict: Dict[str, Any]) -> Dict[str, Any]:
        default_response = {"decision": "deny"}
        try:
            config = Config()
            api_url = config.api_url
            api_key = config.api_key
            allow_self_signed = config.user_config.insecure
        except Exception as e:
            logger.warning("Failed to load config for API call: %s", e)
            return default_response

        try:
            session = create_session(allow_self_signed=allow_self_signed)

            response = session.post(
                urljoin(api_url, "/v1/ai-security/mcp"),
                json=entry_dict,
                headers={
                    "Authorization": f"Token {api_key}",
                    "Content-Type": "application/json",
                },
            )
            logger.warning("API call to /v1/ai-security/mcp: %s", response.json())
            if not response.ok:
                logger.warning(
                    "API call to /v1/ai-security/mcp failed: %s %s",
                    response.status_code,
                    response.text,
                )
                return default_response
            return response.json()
        except Exception as e:
            logger.warning("Failed to send activity to API: %s", e)
            return default_response

    def process_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        server_name, server_config = self.identify_server(event_data)
        return self.log_activity(event_data, server_name, server_config)
