"""
MCP Discovery - Discovers all MCP servers with their tools, scopes, and identities.

This module provides functionality to parse an mcp.json file and return
comprehensive information about each configured MCP server.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ggshield.verticals.mcp_monitor.config import (
    get_mcp_cache_dir,
    load_json_file,
    save_json_file,
)
from ggshield.verticals.mcp_monitor.identity import MCPIdentityMapper
from ggshield.verticals.mcp_monitor.tool_mapping import MCPToolMappingBuilder

DISCOVERY_CACHE_FILENAME = "mcp_discovery_cache.json"


@dataclass
class MCPServerInfo:
    name: str
    command: str
    args: List[str]
    tools: List[str]
    identity: Optional[Dict[str, Any]]
    scopes: Optional[List[str]]
    identity_repr: Optional[str] = None
    env_vars: Dict[str, str] = field(default_factory=dict)
    server_type: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "command": self.command,
            "args": self.args,
            "tools": self.tools,
            "identity": self.identity,
            "identity_repr": self.identity_repr,
            "scopes": self.scopes,
            "env_vars": self.env_vars,
            "server_type": self.server_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MCPServerInfo":
        scopes = data.get("scopes")
        if isinstance(scopes, str):
            scopes = scopes.split() if scopes else []
        return cls(
            name=data.get("name", ""),
            command=data.get("command", ""),
            args=data.get("args", []),
            tools=data.get("tools", []),
            identity=data.get("identity"),
            scopes=scopes,
            identity_repr=data.get("identity_repr"),
            env_vars=data.get("env_vars", {}),
            server_type=data.get("server_type"),
        )


def compute_identity_repr(
    server_name: str, identity: Optional[Dict[str, Any]]
) -> Optional[str]:
    if not identity:
        return None

    server_name_lower = server_name.lower()

    if "clickhouse" in server_name_lower:
        username = identity.get("username")
        return username if username else None

    if "sentry" in server_name_lower:
        user_id = identity.get("user_id")
        return f"user_id:{user_id}" if user_id else None

    if "linear" in server_name_lower:
        client_id = identity.get("client_id")
        return f"client_id:{client_id}" if client_id else None

    if "gitlab" in server_name_lower:
        token_name = identity.get("token_name")
        username = identity.get("username")
        if token_name and username:
            return f"token {token_name} from {username}"
        elif username:
            return username
        return None

    return None


def parse_scopes_to_list(
    scopes: Optional[str], server_name: Optional[str] = None
) -> Optional[List[str]]:
    if not scopes:
        return None

    server_lower = (server_name or "").lower()
    if "clickhouse" in server_lower or scopes.strip().upper().startswith("GRANT"):
        return [scopes.strip()]

    if "\n" in scopes:
        return [line.strip() for line in scopes.strip().split("\n") if line.strip()]

    return scopes.split()


def discover_mcp_servers(
    mcp_json_path: Path,
    fetch_tools: bool = True,
    fetch_identity: bool = True,
    timeout: int = 15,
) -> List[MCPServerInfo]:
    """
    Parse an mcp.json file and return information about all configured MCP servers.

    If fetch_tools is True, queries each server to discover its available tools.
    If fetch_identity is True, queries each server for identity and scope information.
    """
    config = load_json_file(mcp_json_path)
    if not isinstance(config, dict):
        return []

    servers = config.get("mcpServers", {})
    if not servers:
        return []

    tool_builder = MCPToolMappingBuilder(timeout=timeout) if fetch_tools else None
    identity_mapper = MCPIdentityMapper(timeout=timeout) if fetch_identity else None

    results: List[MCPServerInfo] = []

    for server_name, server_config in servers.items():
        command = server_config.get("command", "")
        args = server_config.get("args", [])
        env_vars = server_config.get("env", {})
        server_type = server_config.get("type")

        tools: List[str] = []
        if tool_builder:
            tools = tool_builder.get_tools_from_mcp_server(server_name, server_config)

        identity: Optional[Dict[str, Any]] = None
        scopes_str: Optional[str] = None
        if identity_mapper:
            identity, scopes_str = identity_mapper.get_identity_and_scopes(
                server_name, server_config
            )

        scopes_list = parse_scopes_to_list(scopes_str, server_name)
        identity_repr = compute_identity_repr(server_name, identity)
        sanitized_env = _sanitize_env_vars(env_vars)

        server_info = MCPServerInfo(
            name=server_name,
            command=command,
            args=args,
            tools=tools,
            identity=identity,
            scopes=scopes_list,
            identity_repr=identity_repr,
            env_vars=sanitized_env,
            server_type=server_type,
        )
        results.append(server_info)

    return results


def _sanitize_env_vars(env_vars: Dict[str, str]) -> Dict[str, str]:
    """Remove sensitive values from environment variables, keeping only the keys."""
    sensitive_keywords = ["token", "password", "secret", "key", "auth", "credential"]
    sanitized = {}
    for key, value in env_vars.items():
        key_lower = key.lower()
        if any(keyword in key_lower for keyword in sensitive_keywords):
            sanitized[key] = "***REDACTED***"
        else:
            sanitized[key] = value
    return sanitized


def discover_mcp_servers_from_workspaces(
    workspace_roots: List[str],
    fetch_tools: bool = True,
    fetch_identity: bool = True,
    timeout: int = 15,
) -> List[MCPServerInfo]:
    """
    Discover MCP servers from workspace .cursor/mcp.json files or global config.
    """
    for workspace in workspace_roots:
        workspace_mcp = Path(workspace) / ".cursor" / "mcp.json"
        if workspace_mcp.exists():
            return discover_mcp_servers(
                workspace_mcp,
                fetch_tools=fetch_tools,
                fetch_identity=fetch_identity,
                timeout=timeout,
            )

    global_mcp = Path.home() / ".cursor" / "mcp.json"
    if global_mcp.exists():
        return discover_mcp_servers(
            global_mcp,
            fetch_tools=fetch_tools,
            fetch_identity=fetch_identity,
            timeout=timeout,
        )

    return []


def get_discovery_cache_path() -> Path:
    return get_mcp_cache_dir() / DISCOVERY_CACHE_FILENAME


def save_discovery_cache(servers: List[MCPServerInfo]) -> None:
    """
    Save discovery results to cache. Creates two mappings:
    1. servers: Full server info by server name
    2. tool_to_server: Maps each tool name to its server name for fast lookup
    """
    cache_data: Dict[str, Any] = {
        "servers": {server.name: server.to_dict() for server in servers},
        "tool_to_server": {},
    }

    for server in servers:
        for tool in server.tools:
            if tool:
                cache_data["tool_to_server"][tool] = server.name

    save_json_file(get_discovery_cache_path(), cache_data)


def load_discovery_cache() -> Optional[Dict[str, Any]]:
    """Load discovery cache if it exists."""
    cache_path = get_discovery_cache_path()
    if not cache_path.exists():
        return None

    data = load_json_file(cache_path)
    if isinstance(data, dict) and "servers" in data:
        return data
    return None


def get_server_info_from_cache(server_name: str) -> Optional[MCPServerInfo]:
    """Get server info from cache by server name."""
    cache = load_discovery_cache()
    if not cache:
        return None

    server_data = cache.get("servers", {}).get(server_name)
    if server_data:
        return MCPServerInfo.from_dict(server_data)
    return None


def get_server_info_for_tool(tool_name: str) -> Optional[MCPServerInfo]:
    """Get server info from cache by tool name."""
    cache = load_discovery_cache()
    if not cache:
        return None

    server_name = cache.get("tool_to_server", {}).get(tool_name)
    if not server_name:
        return None

    server_data = cache.get("servers", {}).get(server_name)
    if server_data:
        return MCPServerInfo.from_dict(server_data)
    return None
