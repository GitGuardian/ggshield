"""Tests for the MCP config utilities."""

import json

import pytest

from ggshield.verticals.mcp_monitor.config import (
    extract_host_from_config,
    get_mcp_remote_url,
    load_json_file,
    load_mcp_config,
    save_json_file,
)


class TestLoadJsonFile:
    def test_load_valid_json(self, tmp_path):
        json_file = tmp_path / "test.json"
        json_file.write_text('{"key": "value"}')

        result = load_json_file(json_file)

        assert result == {"key": "value"}

    def test_load_invalid_json(self, tmp_path):
        json_file = tmp_path / "test.json"
        json_file.write_text("not json")

        result = load_json_file(json_file)

        assert result == {}

    def test_load_missing_file(self, tmp_path):
        json_file = tmp_path / "missing.json"

        result = load_json_file(json_file)

        assert result == {}


class TestSaveJsonFile:
    def test_save_dict(self, tmp_path):
        json_file = tmp_path / "test.json"

        save_json_file(json_file, {"key": "value"})

        assert json.loads(json_file.read_text()) == {"key": "value"}

    def test_save_list(self, tmp_path):
        json_file = tmp_path / "test.json"

        save_json_file(json_file, [1, 2, 3])

        assert json.loads(json_file.read_text()) == [1, 2, 3]

    def test_creates_parent_directories(self, tmp_path):
        json_file = tmp_path / "nested" / "dir" / "test.json"

        save_json_file(json_file, {"nested": True})

        assert json_file.exists()
        assert json.loads(json_file.read_text()) == {"nested": True}


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
            "linear": {
                "command": "npx",
                "args": ["-y", "mcp-remote@latest", "https://mcp.linear.app/sse"],
            },
            "clickhouse": {
                "command": "uvx",
                "args": ["mcp-clickhouse"],
                "env": {"CLICKHOUSE_HOST": "clickhouse.example.com"},
            },
        }
    }
    (cursor_dir / "mcp.json").write_text(json.dumps(mcp_config))

    return tmp_path


class TestLoadMcpConfig:
    def test_load_workspace_config(self, temp_dir_with_mcp_config):
        result = load_mcp_config([str(temp_dir_with_mcp_config)])

        assert "mcpServers" in result
        assert "gitlab" in result["mcpServers"]
        assert "linear" in result["mcpServers"]

    def test_load_missing_config(self, tmp_path):
        result = load_mcp_config([str(tmp_path)])

        assert result == {}

    def test_load_first_workspace_with_config(self, temp_dir_with_mcp_config, tmp_path):
        result = load_mcp_config([str(tmp_path), str(temp_dir_with_mcp_config)])

        assert "mcpServers" in result


class TestExtractHostFromConfig:
    def test_extract_from_clickhouse_env(self):
        server_config = {"env": {"CLICKHOUSE_HOST": "clickhouse.example.com"}}

        result = extract_host_from_config(server_config)

        assert result == "clickhouse.example.com"

    def test_extract_from_gitlab_api_url(self):
        server_config = {"env": {"GITLAB_API_URL": "https://gitlab.example.com/api/v4"}}

        result = extract_host_from_config(server_config)

        assert result == "gitlab.example.com"

    def test_extract_from_args_https(self):
        server_config = {"args": ["-y", "mcp-remote", "https://api.example.com/sse"]}

        result = extract_host_from_config(server_config)

        assert result == "api.example.com"

    def test_extract_from_args_http(self):
        server_config = {"args": ["http://localhost:8080/api"]}

        result = extract_host_from_config(server_config)

        assert result == "localhost:8080"

    def test_returns_none_for_empty_config(self):
        result = extract_host_from_config({})

        assert result is None

    def test_returns_none_for_none(self):
        result = extract_host_from_config(None)

        assert result is None


class TestGetMcpRemoteUrl:
    def test_returns_https_url(self):
        server_config = {"args": ["-y", "mcp-remote", "https://mcp.example.com/sse"]}

        result = get_mcp_remote_url(server_config)

        assert result == "https://mcp.example.com/sse"

    def test_returns_http_url(self):
        server_config = {"args": ["http://localhost:8080"]}

        result = get_mcp_remote_url(server_config)

        assert result == "http://localhost:8080"

    def test_returns_none_when_no_url(self):
        server_config = {"args": ["-y", "@zereight/mcp-gitlab"]}

        result = get_mcp_remote_url(server_config)

        assert result is None

    def test_returns_none_for_empty_args(self):
        server_config = {"args": []}

        result = get_mcp_remote_url(server_config)

        assert result is None
