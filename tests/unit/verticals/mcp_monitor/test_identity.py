"""Tests for the MCP identity mapper."""

import json
from unittest.mock import MagicMock, patch

import pytest

from ggshield.verticals.mcp_monitor.identity import (
    MCPIdentityMapper,
    compute_url_hash,
    find_mcp_auth_files,
)


@pytest.fixture
def temp_dir_with_mcp_config(tmp_path):
    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir()

    mcp_config = {
        "mcpServers": {
            "gitlab": {
                "command": "npx",
                "args": ["-y", "@zereight/mcp-gitlab"],
                "env": {"GITLAB_API_URL": "https://gitlab.example.com"},
            },
            "clickhouse": {
                "command": "uvx",
                "args": ["mcp-clickhouse"],
                "env": {
                    "CLICKHOUSE_USER": "test_user",
                    "CLICKHOUSE_HOST": "clickhouse.example.com",
                    "CLICKHOUSE_DATABASE": "test_db",
                },
            },
            "linear": {
                "command": "npx",
                "args": ["-y", "mcp-remote@latest", "https://mcp.linear.app/sse"],
            },
            "sentry": {
                "command": "npx",
                "args": ["-y", "mcp-remote@latest", "https://mcp.sentry.io/sse"],
            },
        }
    }
    (cursor_dir / "mcp.json").write_text(json.dumps(mcp_config))

    return tmp_path


@pytest.fixture
def mapper_with_temp_cache(temp_dir_with_mcp_config, tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    def mock_cache_dir():
        return cache_dir

    monkeypatch.setattr(
        "ggshield.verticals.mcp_monitor.identity.get_mcp_cache_dir", mock_cache_dir
    )

    return MCPIdentityMapper(workspace_roots=[str(temp_dir_with_mcp_config)])


class TestComputeUrlHash:
    def test_computes_md5_hash(self):
        url = "https://mcp.example.com/sse"
        result = compute_url_hash(url)

        assert len(result) == 32
        assert result == compute_url_hash(url)

    def test_different_urls_have_different_hashes(self):
        url1 = "https://mcp.example1.com/sse"
        url2 = "https://mcp.example2.com/sse"

        assert compute_url_hash(url1) != compute_url_hash(url2)


class TestFindMcpAuthFiles:
    def test_finds_auth_files(self, tmp_path, monkeypatch):
        url = "https://mcp.example.com/sse"
        url_hash = compute_url_hash(url)

        mcp_auth_dir = tmp_path / ".mcp-auth"
        version_dir = mcp_auth_dir / "v1"
        version_dir.mkdir(parents=True)

        client_info = {"client_id": "test_client"}
        tokens = {"access_token": "test_token", "scope": "read write"}

        (version_dir / f"{url_hash}_client_info.json").write_text(
            json.dumps(client_info)
        )
        (version_dir / f"{url_hash}_tokens.json").write_text(json.dumps(tokens))

        monkeypatch.setattr(
            "ggshield.verticals.mcp_monitor.identity.MCP_AUTH_DIR", mcp_auth_dir
        )

        found_client_info, found_tokens = find_mcp_auth_files(url)

        assert found_client_info == client_info
        assert found_tokens == tokens

    def test_returns_none_when_no_auth_files(self, tmp_path, monkeypatch):
        mcp_auth_dir = tmp_path / ".mcp-auth"
        mcp_auth_dir.mkdir()

        monkeypatch.setattr(
            "ggshield.verticals.mcp_monitor.identity.MCP_AUTH_DIR", mcp_auth_dir
        )

        client_info, tokens = find_mcp_auth_files("https://mcp.example.com/sse")

        assert client_info is None
        assert tokens is None

    def test_returns_none_when_dir_does_not_exist(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "ggshield.verticals.mcp_monitor.identity.MCP_AUTH_DIR",
            tmp_path / ".mcp-auth-nonexistent",
        )

        client_info, tokens = find_mcp_auth_files("https://mcp.example.com/sse")

        assert client_info is None
        assert tokens is None


class TestMCPIdentityMapperClickhouse:
    def test_get_clickhouse_identity(self, mapper_with_temp_cache):
        server_config = {
            "env": {
                "CLICKHOUSE_USER": "test_user",
                "CLICKHOUSE_HOST": "clickhouse.example.com",
                "CLICKHOUSE_DATABASE": "test_db",
            }
        }

        identity = mapper_with_temp_cache.get_clickhouse_identity(server_config)

        assert identity == {
            "username": "test_user",
            "host": "clickhouse.example.com",
            "database": "test_db",
        }

    def test_returns_none_when_no_user(self, mapper_with_temp_cache):
        server_config = {"env": {"CLICKHOUSE_HOST": "clickhouse.example.com"}}

        identity = mapper_with_temp_cache.get_clickhouse_identity(server_config)

        assert identity is None


class TestMCPIdentityMapperGitlab:
    def test_get_gitlab_identity(self, mapper_with_temp_cache):
        mcp_response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "data": {
                                    "currentUser": {
                                        "id": "gid://gitlab/User/123",
                                        "username": "testuser",
                                        "name": "Test User",
                                        "email": "test@example.com",
                                    }
                                }
                            }
                        ),
                    }
                ]
            },
        }

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=json.dumps(mcp_response),
                returncode=0,
            )

            identity = mapper_with_temp_cache.get_gitlab_identity(
                {"command": "npx", "args": ["-y", "@test/mcp"], "env": {}}
            )

        assert identity == {
            "user_id": "gid://gitlab/User/123",
            "username": "testuser",
            "name": "Test User",
            "email": "test@example.com",
        }

    def test_returns_none_on_timeout(self, mapper_with_temp_cache):
        with patch("subprocess.run") as mock_run:
            from subprocess import TimeoutExpired

            mock_run.side_effect = TimeoutExpired("cmd", 15)

            identity = mapper_with_temp_cache.get_gitlab_identity(
                {"command": "npx", "args": ["-y", "@test/mcp"], "env": {}}
            )

        assert identity is None

    def test_returns_none_when_no_command(self, mapper_with_temp_cache):
        identity = mapper_with_temp_cache.get_gitlab_identity(
            {"command": "", "args": [], "env": {}}
        )

        assert identity is None


class TestMCPIdentityMapperSentry:
    def test_get_sentry_identity_from_token(self, mapper_with_temp_cache, monkeypatch):
        def mock_find_auth_files(url):
            return None, {"access_token": "12345:some_token_data", "scope": "org:read"}

        monkeypatch.setattr(
            "ggshield.verticals.mcp_monitor.identity.find_mcp_auth_files",
            mock_find_auth_files,
        )

        identity = mapper_with_temp_cache.get_sentry_identity(
            {"args": ["https://mcp.sentry.io/sse"]}
        )

        assert identity == {"user_id": "12345"}

    def test_returns_none_when_no_url(self, mapper_with_temp_cache):
        identity = mapper_with_temp_cache.get_sentry_identity({"args": []})

        assert identity is None


class TestMCPIdentityMapperLinear:
    def test_get_linear_identity_from_client_info(
        self, mapper_with_temp_cache, monkeypatch
    ):
        def mock_find_auth_files(url):
            return {"client_id": "abc123", "client_name": "MCP CLI"}, None

        monkeypatch.setattr(
            "ggshield.verticals.mcp_monitor.identity.find_mcp_auth_files",
            mock_find_auth_files,
        )

        identity = mapper_with_temp_cache.get_linear_identity(
            {"args": ["https://mcp.linear.app/sse"]}
        )

        assert identity == {"client_id": "abc123", "client_name": "MCP CLI"}

    def test_returns_none_when_no_url(self, mapper_with_temp_cache):
        identity = mapper_with_temp_cache.get_linear_identity({"args": []})

        assert identity is None


class TestMCPIdentityMapperGetIdentity:
    def test_routes_to_gitlab_by_server_name(self, mapper_with_temp_cache):
        with patch.object(
            mapper_with_temp_cache,
            "get_gitlab_identity",
            return_value={"user_id": "123"},
        ):
            identity = mapper_with_temp_cache.get_identity("gitlab", {})

            assert identity == {"user_id": "123"}

    def test_routes_to_clickhouse_by_server_name(self, mapper_with_temp_cache):
        server_config = {"env": {"CLICKHOUSE_USER": "user"}}

        identity = mapper_with_temp_cache.get_identity("clickhouse", server_config)

        assert identity["username"] == "user"

    def test_routes_to_sentry_by_server_name(self, mapper_with_temp_cache, monkeypatch):
        def mock_find_auth_files(url):
            return None, {"access_token": "999:token"}

        monkeypatch.setattr(
            "ggshield.verticals.mcp_monitor.identity.find_mcp_auth_files",
            mock_find_auth_files,
        )

        identity = mapper_with_temp_cache.get_identity(
            "sentry", {"args": ["https://mcp.sentry.io/sse"]}
        )

        assert identity == {"user_id": "999"}

    def test_fallback_to_clickhouse_then_linear(self, mapper_with_temp_cache):
        server_config = {"env": {"CLICKHOUSE_USER": "user"}}

        identity = mapper_with_temp_cache.get_identity("unknown_server", server_config)

        assert identity["username"] == "user"


class TestMCPIdentityMapperBuildMappings:
    def test_builds_identity_and_scopes_mappings(
        self, mapper_with_temp_cache, monkeypatch
    ):
        def mock_find_auth_files(url):
            if "sentry" in url:
                return None, {"access_token": "111:token", "scope": "org:read"}
            if "linear" in url:
                return {"client_id": "abc"}, {"scope": "openid"}
            return None, None

        monkeypatch.setattr(
            "ggshield.verticals.mcp_monitor.identity.find_mcp_auth_files",
            mock_find_auth_files,
        )

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()

            identity_mapping, scopes_mapping = mapper_with_temp_cache.build_mappings()

        assert "clickhouse" in identity_mapping
        assert identity_mapping["clickhouse"]["username"] == "test_user"

        assert "sentry" in identity_mapping
        assert identity_mapping["sentry"]["user_id"] == "111"

        assert scopes_mapping.get("sentry") == "org:read"
        assert scopes_mapping.get("linear") == "openid"
