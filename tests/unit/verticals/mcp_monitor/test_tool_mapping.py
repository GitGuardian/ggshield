"""Tests for the MCP tool mapping builder."""

import json
from unittest.mock import MagicMock, patch

import pytest

from ggshield.verticals.mcp_monitor.tool_mapping import MCPToolMappingBuilder


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
            },
        }
    }
    (cursor_dir / "mcp.json").write_text(json.dumps(mcp_config))

    return tmp_path


@pytest.fixture
def builder_with_temp_cache(temp_dir_with_mcp_config, tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    def mock_cache_dir():
        return cache_dir

    monkeypatch.setattr(
        "ggshield.verticals.mcp_monitor.tool_mapping.get_mcp_cache_dir", mock_cache_dir
    )

    return MCPToolMappingBuilder(workspace_roots=[str(temp_dir_with_mcp_config)])


class TestGetToolsFromMcpServer:
    def test_returns_tools_from_mcp_response(self, builder_with_temp_cache):
        mcp_response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {"name": "list_projects", "description": "List projects"},
                    {"name": "create_issue", "description": "Create issue"},
                ]
            },
        }

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=json.dumps(mcp_response),
                returncode=0,
            )

            tools = builder_with_temp_cache.get_tools_from_mcp_server(
                "gitlab",
                {"command": "npx", "args": ["-y", "@test/mcp"], "env": {}},
            )

        assert tools == ["list_projects", "create_issue"]

    def test_handles_multiline_output(self, builder_with_temp_cache):
        mcp_response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "tool1"}]},
        }

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=f"some log line\n{json.dumps(mcp_response)}\n",
                returncode=0,
            )

            tools = builder_with_temp_cache.get_tools_from_mcp_server(
                "test", {"command": "test", "args": [], "env": {}}
            )

        assert tools == ["tool1"]

    def test_returns_empty_on_timeout(self, builder_with_temp_cache):
        with patch("subprocess.run") as mock_run:
            from subprocess import TimeoutExpired

            mock_run.side_effect = TimeoutExpired("cmd", 10)

            tools = builder_with_temp_cache.get_tools_from_mcp_server(
                "test", {"command": "test", "args": [], "env": {}}
            )

        assert tools == []

    def test_returns_empty_on_command_not_found(self, builder_with_temp_cache):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()

            tools = builder_with_temp_cache.get_tools_from_mcp_server(
                "test", {"command": "nonexistent", "args": [], "env": {}}
            )

        assert tools == []

    def test_returns_empty_when_no_command(self, builder_with_temp_cache):
        tools = builder_with_temp_cache.get_tools_from_mcp_server(
            "test", {"command": "", "args": [], "env": {}}
        )

        assert tools == []

    def test_returns_empty_on_invalid_response(self, builder_with_temp_cache):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="not json at all",
                returncode=0,
            )

            tools = builder_with_temp_cache.get_tools_from_mcp_server(
                "test", {"command": "test", "args": [], "env": {}}
            )

        assert tools == []


class TestBuildToolMapping:
    def test_builds_mapping_from_multiple_servers(self, builder_with_temp_cache):
        gitlab_response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": [{"name": "list_projects"}, {"name": "create_issue"}]},
        }
        linear_response = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [{"name": "list_documents"}, {"name": "create_comment"}]
            },
        }

        def mock_subprocess_run(cmd, **kwargs):
            if "@zereight/mcp-gitlab" in cmd:
                return MagicMock(stdout=json.dumps(gitlab_response))
            if "mcp.linear.app" in " ".join(cmd):
                return MagicMock(stdout=json.dumps(linear_response))
            return MagicMock(stdout="")

        with patch("subprocess.run", side_effect=mock_subprocess_run):
            mapping = builder_with_temp_cache.build_tool_mapping()

        assert mapping["list_projects"] == "gitlab"
        assert mapping["create_issue"] == "gitlab"
        assert mapping["list_documents"] == "linear"
        assert mapping["create_comment"] == "linear"

    def test_preserves_existing_mapping(self, builder_with_temp_cache):
        existing_mapping = {"existing_tool": "existing_server"}
        builder_with_temp_cache.tool_mapping_path.write_text(
            json.dumps(existing_mapping)
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="")

            mapping = builder_with_temp_cache.build_tool_mapping()

        assert mapping["existing_tool"] == "existing_server"

    def test_handles_servers_with_no_tools(self, builder_with_temp_cache):
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()

            mapping = builder_with_temp_cache.build_tool_mapping()

        assert mapping == {}


class TestSaveMapping:
    def test_saves_mapping_to_file(self, builder_with_temp_cache):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {"tools": [{"name": "test_tool"}]},
                    }
                )
            )
            builder_with_temp_cache.save_mapping()

        assert builder_with_temp_cache.tool_mapping_path.exists()
        mapping = json.loads(builder_with_temp_cache.tool_mapping_path.read_text())
        assert "test_tool" in mapping

    def test_saves_custom_mapping(self, builder_with_temp_cache):
        custom_mapping = {"custom_tool": "custom_server"}
        builder_with_temp_cache.save_mapping(custom_mapping)

        mapping = json.loads(builder_with_temp_cache.tool_mapping_path.read_text())
        assert mapping == custom_mapping
