"""
MCP Tool Mapping Builder - Builds mappings of MCP tools to their servers.

This module queries each configured MCP server to discover its available tools
and creates a mapping file for fast lookups.
"""

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ggshield.verticals.mcp_monitor.config import (
    get_mcp_cache_dir,
    load_json_file,
    load_mcp_config,
    save_json_file,
)


@dataclass
class MCPToolMappingBuilder:
    workspace_roots: List[str] = field(default_factory=list)
    timeout: int = 10

    @property
    def cache_dir(self) -> Path:
        return get_mcp_cache_dir()

    @property
    def tool_mapping_path(self) -> Path:
        return self.cache_dir / "mcp_tool_mapping.json"

    def get_tools_from_mcp_server(
        self, server_name: str, server_config: Dict[str, Any]
    ) -> List[str]:
        command = server_config.get("command", "")
        args = server_config.get("args", [])
        env = server_config.get("env", {})

        if not command:
            return []

        full_command = [command] + args

        request = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        )

        try:
            proc_env = os.environ.copy()
            proc_env.update(env)

            result = subprocess.run(
                full_command,
                input=request + "\n",
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env=proc_env,
            )

            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                try:
                    response = json.loads(line)
                    if "result" in response and "tools" in response["result"]:
                        return [
                            tool.get("name", "") for tool in response["result"]["tools"]
                        ]
                except json.JSONDecodeError:
                    continue

        except (
            subprocess.TimeoutExpired,
            subprocess.SubprocessError,
            FileNotFoundError,
        ):
            pass

        return []

    def build_tool_mapping(self) -> Dict[str, str]:
        mcp_config = load_mcp_config(self.workspace_roots)
        existing_mapping = load_json_file(self.tool_mapping_path)
        if not isinstance(existing_mapping, dict):
            existing_mapping = {}

        mapping: Dict[str, str] = dict(existing_mapping)

        for server_name, server_config in mcp_config.get("mcpServers", {}).items():
            tools = self.get_tools_from_mcp_server(server_name, server_config)
            for tool in tools:
                if tool:
                    mapping[tool] = server_name

        return mapping

    def save_mapping(self, mapping: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        if mapping is None:
            mapping = self.build_tool_mapping()
        save_json_file(self.tool_mapping_path, mapping)
        return mapping
