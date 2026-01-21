"""
MCP Monitor - Track and log MCP tool executions with server identification.

This module provides functionality to:
1. Identify which MCP server a tool belongs to
2. Log MCP activity with identity and scope information
3. Build tool-to-server mappings dynamically
4. Discover all MCP servers with their tools, scopes, and identities
"""

from ggshield.verticals.mcp_monitor.activity import (
    MCPActivityMonitor,
    create_activity_entry,
)
from ggshield.verticals.mcp_monitor.config import (
    load_mcp_config,
)
from ggshield.verticals.mcp_monitor.discovery import (
    MCPServerInfo,
    discover_mcp_servers,
    discover_mcp_servers_from_workspaces,
    get_server_info_for_tool,
    load_discovery_cache,
    save_discovery_cache,
)
from ggshield.verticals.mcp_monitor.tool_mapping import (
    MCPToolMappingBuilder,
)

__all__ = [
    "MCPActivityMonitor",
    "MCPServerInfo",
    "MCPToolMappingBuilder",
    "create_activity_entry",
    "discover_mcp_servers",
    "discover_mcp_servers_from_workspaces",
    "get_server_info_for_tool",
    "load_discovery_cache",
    "load_mcp_config",
    "save_discovery_cache",
]
