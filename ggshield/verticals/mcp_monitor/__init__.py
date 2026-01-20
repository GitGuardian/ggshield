"""
MCP Monitor - Track and log MCP tool executions with server identification.

This module provides functionality to:
1. Identify which MCP server a tool belongs to
2. Log MCP activity with identity and scope information
3. Build tool-to-server mappings dynamically
"""

from ggshield.verticals.mcp_monitor.activity import (
    MCPActivityMonitor,
    create_activity_entry,
)
from ggshield.verticals.mcp_monitor.config import (
    load_mcp_config,
)
from ggshield.verticals.mcp_monitor.tool_mapping import (
    MCPToolMappingBuilder,
)

__all__ = [
    "MCPActivityMonitor",
    "MCPToolMappingBuilder",
    "create_activity_entry",
    "load_mcp_config",
]
