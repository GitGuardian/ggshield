"""
MCP Identity Mapper - Builds mappings of MCP servers to user identity and scopes.

This module queries each MCP server to determine:
1. The authenticated user identity (user ID, username, email, etc.)
2. The OAuth scopes/permissions granted to the MCP server
"""

import base64
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen

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

    def get_gitlab_identity_and_scopes(
        self, server_config: Dict[str, Any]
    ) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
        env_vars = server_config.get("env", {})
        api_url = env_vars.get("GITLAB_API_URL")
        token = env_vars.get("GITLAB_PERSONAL_ACCESS_TOKEN")

        if not api_url or not token:
            return None, None

        headers = {"PRIVATE-TOKEN": token}
        base_url = api_url.rstrip("/")

        try:
            token_url = f"{base_url}/api/v4/personal_access_tokens/self"
            token_req = Request(token_url, headers=headers)
            with urlopen(token_req, timeout=10) as response:
                token_info = json.loads(response.read().decode())

            scopes = token_info.get("scopes", [])
            scopes_str = " ".join(scopes) if scopes else None

            user_url = f"{base_url}/api/v4/user"
            user_req = Request(user_url, headers=headers)
            with urlopen(user_req, timeout=10) as response:
                user_info = json.loads(response.read().decode())

            identity = {
                "user_id": user_info.get("id"),
                "username": user_info.get("username"),
                "name": user_info.get("name"),
                "email": user_info.get("email"),
                "token_name": token_info.get("name"),
            }

            return identity, scopes_str
        except Exception:
            pass

        return None, None

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

    def get_clickhouse_identity_and_scopes(
        self, server_config: Dict[str, Any]
    ) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
        env_vars = server_config.get("env", {})
        user = env_vars.get("CLICKHOUSE_USER")
        password = env_vars.get("CLICKHOUSE_PASSWORD", "")
        host = env_vars.get("CLICKHOUSE_HOST")
        port = env_vars.get("CLICKHOUSE_PORT", "8443")
        secure = env_vars.get("CLICKHOUSE_SECURE", "false").lower() == "true"
        database = env_vars.get("CLICKHOUSE_DATABASE")

        if not user or not host:
            return None, None

        identity = {
            "username": user,
            "host": host,
            "database": database,
        }

        scopes = None
        try:
            protocol = "https" if secure else "http"
            url = f"{protocol}://{host}:{port}/?query=SHOW+GRANTS+FOR+CURRENT_USER"
            req = Request(url)

            credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
            req.add_header("Authorization", f"Basic {credentials}")

            with urlopen(req, timeout=10) as response:
                grants = response.read().decode().strip()
                if grants:
                    scopes = grants
        except Exception:
            pass

        return identity, scopes

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
        if url:
            _, tokens = find_mcp_auth_files(url)
            if tokens:
                return tokens.get("scope")

        return None

    def get_gitlab_scopes(self, server_config: Dict[str, Any]) -> Optional[str]:
        env_vars = server_config.get("env", {})
        api_url = env_vars.get("GITLAB_API_URL")
        token = env_vars.get("GITLAB_PERSONAL_ACCESS_TOKEN")

        if not api_url or not token:
            return None

        try:
            url = f"{api_url.rstrip('/')}/api/v4/personal_access_tokens/self"
            req = Request(url, headers={"PRIVATE-TOKEN": token})
            with urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
                scopes = data.get("scopes", [])
                if scopes:
                    return " ".join(scopes)
        except Exception:
            pass

        return None

    def get_identity_and_scopes(
        self, server_name: str, server_config: Dict[str, Any]
    ) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
        server_name_lower = server_name.lower()

        if "gitlab" in server_name_lower:
            return self.get_gitlab_identity_and_scopes(server_config)
        elif "sentry" in server_name_lower:
            identity = self.get_sentry_identity(server_config)
            scopes = self.get_scopes_from_tokens(server_config)
            return identity, scopes
        elif "clickhouse" in server_name_lower:
            return self.get_clickhouse_identity_and_scopes(server_config)
        elif "linear" in server_name_lower:
            identity = self.get_linear_identity(server_config)
            scopes = self.get_scopes_from_tokens(server_config)
            return identity, scopes
        else:
            identity, scopes = self.get_clickhouse_identity_and_scopes(server_config)
            if not identity:
                identity = self.get_linear_identity(server_config)
                scopes = self.get_scopes_from_tokens(server_config)
            return identity, scopes

    def build_mappings(self) -> tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
        mcp_config = load_mcp_config(self.workspace_roots)

        identity_mapping: Dict[str, Dict[str, Any]] = {}
        scopes_mapping: Dict[str, str] = {}

        for server_name, server_config in mcp_config.get("mcpServers", {}).items():
            identity, scopes = self.get_identity_and_scopes(server_name, server_config)
            if identity:
                identity_mapping[server_name] = identity
            if scopes:
                scopes_mapping[server_name] = scopes

        save_json_file(self.identity_mapping_path, identity_mapping)
        save_json_file(self.scopes_mapping_path, scopes_mapping)

        return identity_mapping, scopes_mapping
