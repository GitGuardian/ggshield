"""
MCP Identity Mapper - Builds mappings of MCP servers to user identity and scopes.

This module queries each MCP server to determine:
1. The authenticated user identity (user ID, username, email, etc.)
2. The OAuth scopes/permissions granted to the MCP server
"""

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from ggshield.verticals.mcp_monitor.config import (
    get_mcp_cache_dir,
    get_mcp_remote_url,
    load_json_file,
    load_mcp_config,
    save_json_file,
)

MCP_AUTH_DIR = Path.home() / ".mcp-auth"


def compute_url_hash(url: str) -> str:
    return hashlib.md5(url.encode()).hexdigest()


def find_mcp_auth_files(
    url: str,
) -> tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    url_hash = compute_url_hash(url)

    if not MCP_AUTH_DIR.exists():
        return None, None

    for version_dir in MCP_AUTH_DIR.iterdir():
        if not version_dir.is_dir():
            continue

        client_info_path = version_dir / f"{url_hash}_client_info.json"
        tokens_path = version_dir / f"{url_hash}_tokens.json"

        if client_info_path.exists() and tokens_path.exists():
            client_info = load_json_file(client_info_path)
            tokens = load_json_file(tokens_path)
            if isinstance(client_info, dict) and isinstance(tokens, dict):
                return client_info, tokens

    return None, None


@dataclass
class MCPIdentityMapper:
    workspace_roots: List[str] = field(default_factory=list)
    timeout: int = 15

    @property
    def cache_dir(self) -> Path:
        return get_mcp_cache_dir()

    @property
    def identity_mapping_path(self) -> Path:
        return self.cache_dir / "mcp_identity_mapping.json"

    @property
    def scopes_mapping_path(self) -> Path:
        return self.cache_dir / "mcp_scopes_mapping.json"

    def get_gitlab_identity(
        self, server_config: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        command = server_config.get("command", "")
        args = server_config.get("args", [])
        env_vars = server_config.get("env", {})

        if not command:
            return None

        full_command = [command] + args

        graphql_query = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "execute_graphql",
                "arguments": {
                    "query": "query { currentUser { id username name email } }"
                },
            },
        }

        try:
            proc_env = os.environ.copy()
            proc_env.update(env_vars)

            result = subprocess.run(
                full_command,
                input=json.dumps(graphql_query) + "\n",
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
                    if "result" in response:
                        content = response.get("result", {}).get("content", [])
                        for item in content:
                            if item.get("type") == "text":
                                data = json.loads(item.get("text", "{}"))
                                if "data" in data and "currentUser" in data["data"]:
                                    user = data["data"]["currentUser"]
                                    return {
                                        "user_id": user.get("id"),
                                        "username": user.get("username"),
                                        "name": user.get("name"),
                                        "email": user.get("email"),
                                    }
                except json.JSONDecodeError:
                    continue

        except (
            subprocess.TimeoutExpired,
            subprocess.SubprocessError,
            FileNotFoundError,
        ):
            pass

        return None

    def get_sentry_identity(
        self, server_config: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        url = get_mcp_remote_url(server_config)
        if not url:
            return None

        _, tokens = find_mcp_auth_files(url)

        if tokens:
            access_token = tokens.get("access_token", "")
            if ":" in access_token:
                user_id = access_token.split(":")[0]
                if user_id.isdigit():
                    return {"user_id": user_id}

        return None

    def get_clickhouse_identity(
        self, server_config: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        env_vars = server_config.get("env", {})
        user = env_vars.get("CLICKHOUSE_USER")

        if user:
            return {
                "username": user,
                "host": env_vars.get("CLICKHOUSE_HOST"),
                "database": env_vars.get("CLICKHOUSE_DATABASE"),
            }

        return None

    def get_linear_identity(
        self, server_config: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        url = get_mcp_remote_url(server_config)
        if not url:
            return None

        client_info, _ = find_mcp_auth_files(url)
        if client_info:
            return {
                "client_id": client_info.get("client_id"),
                "client_name": client_info.get("client_name"),
            }

        return None

    def get_scopes_from_tokens(self, server_config: Dict[str, Any]) -> Optional[str]:
        url = get_mcp_remote_url(server_config)
        if not url:
            return None

        _, tokens = find_mcp_auth_files(url)

        if tokens:
            return tokens.get("scope")

        return None

    def get_identity(
        self, server_name: str, server_config: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        server_name_lower = server_name.lower()

        if "gitlab" in server_name_lower:
            return self.get_gitlab_identity(server_config)
        elif "sentry" in server_name_lower:
            return self.get_sentry_identity(server_config)
        elif "clickhouse" in server_name_lower:
            return self.get_clickhouse_identity(server_config)
        elif "linear" in server_name_lower:
            return self.get_linear_identity(server_config)
        else:
            identity = self.get_clickhouse_identity(server_config)
            if not identity:
                identity = self.get_linear_identity(server_config)
            return identity

    def build_identity_mapping(
        self, mcp_config: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        mapping: Dict[str, Dict[str, Any]] = {}

        for server_name, server_config in mcp_config.get("mcpServers", {}).items():
            identity = self.get_identity(server_name, server_config)
            if identity:
                mapping[server_name] = identity

        return mapping

    def build_scopes_mapping(self, mcp_config: Dict[str, Any]) -> Dict[str, str]:
        mapping: Dict[str, str] = {}

        for server_name, server_config in mcp_config.get("mcpServers", {}).items():
            scopes = self.get_scopes_from_tokens(server_config)
            if scopes:
                mapping[server_name] = scopes

        return mapping

    def build_mappings(self) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
        mcp_config = load_mcp_config(self.workspace_roots)

        identity_mapping = self.build_identity_mapping(mcp_config)
        scopes_mapping = self.build_scopes_mapping(mcp_config)

        save_json_file(self.identity_mapping_path, identity_mapping)
        save_json_file(self.scopes_mapping_path, scopes_mapping)

        return identity_mapping, scopes_mapping
