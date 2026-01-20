"""Tests for the MCP activity monitor."""

import json

import pytest

from ggshield.verticals.mcp_monitor.activity import (
    MCPActivityMonitor,
    create_activity_entry,
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
def monitor_with_temp_cache(temp_dir_with_mcp_config, tmp_path, monkeypatch):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()

    def mock_cache_dir():
        return cache_dir

    def mock_output_dir():
        return output_dir

    monkeypatch.setattr(
        "ggshield.verticals.mcp_monitor.activity.get_mcp_cache_dir", mock_cache_dir
    )
    monkeypatch.setattr(
        "ggshield.verticals.mcp_monitor.activity.get_mcp_output_dir", mock_output_dir
    )

    return MCPActivityMonitor(workspace_roots=[str(temp_dir_with_mcp_config)])


class TestCreateActivityEntry:
    def test_creates_entry_with_all_fields(self):
        entry = create_activity_entry(
            server_name="gitlab",
            server_config={"env": {"GITLAB_API_URL": "https://gitlab.example.com"}},
            tool_name="list_projects",
            user_email="user@example.com",
            identity_mapping={"gitlab": {"user_id": "123", "username": "user"}},
            scopes_mapping={"gitlab": "api read_user"},
        )

        assert entry.service == "gitlab"
        assert entry.host == "gitlab.example.com"
        assert entry.cursor_email == "user@example.com"
        assert entry.tool == "list_projects"
        assert entry.identity == {"user_id": "123", "username": "user"}
        assert entry.scopes == "api read_user"
        assert entry.timestamp is not None

    def test_creates_entry_with_none_server(self):
        entry = create_activity_entry(
            server_name=None,
            server_config=None,
            tool_name="unknown_tool",
            user_email="user@example.com",
            identity_mapping={},
            scopes_mapping={},
        )

        assert entry.service is None
        assert entry.host is None
        assert entry.identity is None
        assert entry.scopes is None


class TestMCPActivityMonitorFindServer:
    def test_find_server_by_full_command(self, monitor_with_temp_cache):
        server_name, server_config = monitor_with_temp_cache.find_server_by_command(
            "npx -y mcp-remote@latest https://mcp.linear.app/sse"
        )

        assert server_name == "linear"
        assert server_config["command"] == "npx"

    def test_find_server_by_uvx_command(self, monitor_with_temp_cache):
        server_name, server_config = monitor_with_temp_cache.find_server_by_command(
            "uvx mcp-clickhouse"
        )

        assert server_name == "clickhouse"

    def test_no_match_empty_command(self, monitor_with_temp_cache):
        server_name, server_config = monitor_with_temp_cache.find_server_by_command("")

        assert server_name is None
        assert server_config is None

    def test_no_match_unknown_command(self, monitor_with_temp_cache):
        server_name, server_config = monitor_with_temp_cache.find_server_by_command(
            "unknown-command"
        )

        assert server_name is None
        assert server_config is None


class TestMCPActivityMonitorToolMapping:
    def test_find_mapped_tool(self, monitor_with_temp_cache):
        monitor_with_temp_cache.learn_tool_mapping("list_projects", "gitlab")

        server_name, server_config = (
            monitor_with_temp_cache.find_server_by_tool_mapping("list_projects")
        )

        assert server_name == "gitlab"
        assert "GITLAB_API_URL" in server_config["env"]

    def test_no_mapping_for_unknown_tool(self, monitor_with_temp_cache):
        server_name, server_config = (
            monitor_with_temp_cache.find_server_by_tool_mapping("unknown_tool")
        )

        assert server_name is None
        assert server_config is None

    def test_learn_tool_mapping(self, monitor_with_temp_cache):
        monitor_with_temp_cache.learn_tool_mapping("new_tool", "gitlab")

        assert monitor_with_temp_cache.tool_mapping["new_tool"] == "gitlab"

    def test_skip_learning_empty_values(self, monitor_with_temp_cache):
        monitor_with_temp_cache.learn_tool_mapping("", "gitlab")
        monitor_with_temp_cache.learn_tool_mapping("tool", "")

        assert "" not in monitor_with_temp_cache.tool_mapping
        assert "tool" not in monitor_with_temp_cache.tool_mapping


class TestMCPActivityMonitorCache:
    def test_cache_and_retrieve(self, monitor_with_temp_cache):
        cache_key = "gen123:tool_name"
        server_config = {"command": "test"}

        monitor_with_temp_cache.cache_server_info(cache_key, "gitlab", server_config)
        name, config = monitor_with_temp_cache.get_cached_server_info(cache_key)

        assert name == "gitlab"
        assert config == server_config

    def test_retrieve_missing_key(self, monitor_with_temp_cache):
        name, config = monitor_with_temp_cache.get_cached_server_info("missing_key")

        assert name is None
        assert config is None

    def test_skip_caching_none_server(self, monitor_with_temp_cache):
        monitor_with_temp_cache.cache_server_info("key", None, None)

        name, config = monitor_with_temp_cache.get_cached_server_info("key")
        assert name is None


class TestMCPActivityMonitorGetCacheKey:
    def test_generates_key(self, monitor_with_temp_cache):
        data = {"generation_id": "abc123", "tool_name": "my_tool"}

        key = monitor_with_temp_cache.get_cache_key(data)

        assert key == "abc123:my_tool"

    def test_handles_missing_fields(self, monitor_with_temp_cache):
        data = {}

        key = monitor_with_temp_cache.get_cache_key(data)

        assert key == ":"


class TestMCPActivityMonitorProcessEvent:
    def test_before_execution_with_command(self, monitor_with_temp_cache):
        event_data = {
            "workspace_roots": [],
            "tool_name": "list_documents",
            "command": "npx -y mcp-remote@latest https://mcp.linear.app/sse",
            "hook_event_name": "beforeMCPExecution",
            "generation_id": "gen123",
            "tool_input": "{}",
        }

        response = monitor_with_temp_cache.process_event(event_data)

        assert response == {"decision": "allow"}
        assert monitor_with_temp_cache.tool_mapping.get("list_documents") == "linear"

    def test_after_execution_does_not_log_info(self, monitor_with_temp_cache):
        event_data = {
            "workspace_roots": [],
            "tool_name": "test_tool",
            "command": "",
            "hook_event_name": "afterMCPExecution",
            "generation_id": "gen123",
        }

        response = monitor_with_temp_cache.process_event(event_data)

        assert response == {"decision": "allow"}
        assert not monitor_with_temp_cache.log_info_path.exists()

    def test_logs_activity_for_before_execution(self, monitor_with_temp_cache):
        event_data = {
            "workspace_roots": [],
            "tool_name": "test_tool",
            "command": "uvx mcp-clickhouse",
            "hook_event_name": "beforeMCPExecution",
            "generation_id": "gen456",
            "user_email": "user@example.com",
        }

        monitor_with_temp_cache.process_event(event_data)

        assert monitor_with_temp_cache.log_info_path.exists()
        entries = json.loads(monitor_with_temp_cache.log_info_path.read_text())
        assert len(entries) == 1
        assert entries[0]["service"] == "clickhouse"
        assert entries[0]["tool"] == "test_tool"
        assert entries[0]["cursor_email"] == "user@example.com"
