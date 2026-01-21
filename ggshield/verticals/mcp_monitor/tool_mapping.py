"""
MCP Tool Mapping Builder - Builds mappings of MCP tools to their servers.

This module queries each configured MCP server to discover its available tools
and creates a mapping file for fast lookups.
"""

import json
import os
import queue
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from ggshield.verticals.mcp_monitor.config import (
    get_mcp_cache_dir,
    get_mcp_remote_url,
    load_json_file,
    load_mcp_config,
    save_json_file,
)
from ggshield.verticals.mcp_monitor.identity import (
    find_mcp_auth_files,
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
        remote_url = get_mcp_remote_url(server_config)
        if remote_url:
            tools = self._get_tools_from_remote_server(remote_url)
            if tools:
                return tools

        return self._get_tools_from_stdio_server(server_config)

    def _get_tools_from_remote_server(self, remote_url: str) -> List[str]:
        _, tokens = find_mcp_auth_files(remote_url)
        if not tokens:
            return []

        access_token = tokens.get("access_token")
        if not access_token:
            return []

        if remote_url.rstrip("/").endswith("/sse"):
            return self._get_tools_from_sse_server(remote_url, access_token)

        mcp_url = remote_url.rstrip("/")
        if not mcp_url.endswith("/mcp"):
            mcp_url = mcp_url + "/mcp"

        request_body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        ).encode("utf-8")

        try:
            req = Request(
                mcp_url,
                data=request_body,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
                method="POST",
            )

            with urlopen(req, timeout=self.timeout) as response:
                content_type = response.headers.get("Content-Type", "")

                if "text/event-stream" in content_type:
                    return self._parse_sse_tools_response(response)
                else:
                    return self._parse_json_tools_response(response.read().decode())

        except (URLError, TimeoutError, json.JSONDecodeError):
            pass

        return []

    def _get_tools_from_sse_server(self, sse_url: str, access_token: str) -> List[str]:
        base_url = sse_url.rstrip("/")
        if base_url.endswith("/sse"):
            base_url = base_url[:-4]

        results_queue: queue.Queue[Dict[str, Any]] = queue.Queue()
        session_queue: queue.Queue[str] = queue.Queue()
        stop_event = threading.Event()

        def read_sse() -> None:
            try:
                req = Request(
                    sse_url,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "text/event-stream",
                    },
                )
                with urlopen(req, timeout=self.timeout) as resp:
                    current_event = None
                    while not stop_event.is_set():
                        line = resp.readline()
                        if not line:
                            break
                        line_str = line.decode("utf-8").strip()
                        if line_str.startswith("event:"):
                            current_event = line_str[6:].strip()
                        elif line_str.startswith("data:"):
                            data = line_str[5:].strip()
                            if current_event == "endpoint":
                                session_queue.put(data)
                            elif current_event == "message":
                                try:
                                    parsed = json.loads(data)
                                    results_queue.put(parsed)
                                except json.JSONDecodeError:
                                    pass
            except Exception:
                pass

        sse_thread = threading.Thread(target=read_sse, daemon=True)
        sse_thread.start()

        try:
            session_endpoint = session_queue.get(timeout=self.timeout)
            message_url = f"{base_url}{session_endpoint}"

            init_request = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {
                            "name": "ggshield-mcp-discovery",
                            "version": "1.0",
                        },
                    },
                }
            )
            req = Request(
                message_url,
                data=init_request.encode(),
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            urlopen(req, timeout=self.timeout)

            results_queue.get(timeout=self.timeout)

            tools_request = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {},
                }
            )
            req = Request(
                message_url,
                data=tools_request.encode(),
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            urlopen(req, timeout=self.timeout)

            tools_response = results_queue.get(timeout=self.timeout)
            if "result" in tools_response and "tools" in tools_response["result"]:
                return [
                    tool.get("name", "") for tool in tools_response["result"]["tools"]
                ]

        except (queue.Empty, URLError, TimeoutError):
            pass
        finally:
            stop_event.set()

        return []

    def _parse_sse_tools_response(self, response: Any) -> List[str]:
        for line in response:
            line_str = line.decode("utf-8").strip()
            if line_str.startswith("data:"):
                data = line_str[5:].strip()
                try:
                    parsed = json.loads(data)
                    if "result" in parsed and "tools" in parsed["result"]:
                        return [
                            tool.get("name", "") for tool in parsed["result"]["tools"]
                        ]
                except json.JSONDecodeError:
                    continue
        return []

    def _parse_json_tools_response(self, content: str) -> List[str]:
        for line in content.strip().split("\n"):
            if not line:
                continue
            try:
                parsed = json.loads(line)
                if "result" in parsed and "tools" in parsed["result"]:
                    return [tool.get("name", "") for tool in parsed["result"]["tools"]]
            except json.JSONDecodeError:
                continue
        return []

    def _get_tools_from_stdio_server(self, server_config: Dict[str, Any]) -> List[str]:
        command = server_config.get("command", "")
        args = server_config.get("args", [])
        env = server_config.get("env", {})

        if not command:
            return []

        full_command = [command] + args

        init_request = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "ggshield-mcp-discovery", "version": "1.0"},
                },
            }
        )
        tools_request = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        )

        full_input = init_request + "\n" + tools_request + "\n"

        try:
            proc_env = os.environ.copy()
            proc_env.update(env)

            result = subprocess.run(
                full_command,
                input=full_input,
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

    def _is_remote_server(self, server_config: Dict[str, Any]) -> bool:
        return get_mcp_remote_url(server_config) is not None

    def build_tool_mapping(self) -> Dict[str, str]:
        mcp_config = load_mcp_config(self.workspace_roots)
        existing_mapping = load_json_file(self.tool_mapping_path)
        if not isinstance(existing_mapping, dict):
            existing_mapping = {}

        mapping: Dict[str, str] = dict(existing_mapping)
        server_configs = mcp_config.get("mcpServers", {})

        for server_name, server_config in server_configs.items():
            is_remote = self._is_remote_server(server_config)
            tools = self.get_tools_from_mcp_server(server_name, server_config)
            for tool in tools:
                if tool:
                    if tool in mapping and mapping[tool] != server_name:
                        existing_server_config = server_configs.get(mapping[tool], {})
                        existing_is_remote = self._is_remote_server(
                            existing_server_config
                        )
                        if existing_is_remote and not is_remote:
                            mapping[tool] = server_name
                    else:
                        mapping[tool] = server_name

        return mapping

    def save_mapping(self, mapping: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        if mapping is None:
            mapping = self.build_tool_mapping()
        save_json_file(self.tool_mapping_path, mapping)
        return mapping
