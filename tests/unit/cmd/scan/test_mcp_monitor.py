"""Tests for the mcp-monitor command."""

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from ggshield.cmd.secret.scan.mcp_monitor import (
    MCP_MONITOR_EVENT_HANDLERS,
    handle_after_mcp_execution,
    handle_before_mcp_execution,
    handle_session_start,
    mcp_monitor_cmd,
    process_mcp_monitor_event,
)
from ggshield.core.cursor import CursorEventType


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
        }
    }
    (cursor_dir / "mcp.json").write_text(json.dumps(mcp_config))

    return tmp_path


class TestEventHandlers:
    def test_handlers_registered_for_supported_events(self):
        assert CursorEventType.BEFORE_MCP_EXECUTION in MCP_MONITOR_EVENT_HANDLERS
        assert CursorEventType.AFTER_MCP_EXECUTION in MCP_MONITOR_EVENT_HANDLERS
        assert CursorEventType.SESSION_START in MCP_MONITOR_EVENT_HANDLERS

    def test_before_mcp_execution_returns_allow(self, tmp_path, monkeypatch):
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
            "ggshield.verticals.mcp_monitor.activity.get_mcp_output_dir",
            mock_output_dir,
        )

        event_data = {
            "workspace_roots": [str(tmp_path)],
            "tool_name": "test_tool",
            "command": "",
            "hook_event_name": "beforeMCPExecution",
            "generation_id": "gen123",
        }

        response = handle_before_mcp_execution(event_data)

        assert response == {"decision": "allow"}

    def test_after_mcp_execution_returns_allow(self, tmp_path, monkeypatch):
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
            "ggshield.verticals.mcp_monitor.activity.get_mcp_output_dir",
            mock_output_dir,
        )

        event_data = {
            "workspace_roots": [str(tmp_path)],
            "tool_name": "test_tool",
            "command": "",
            "hook_event_name": "afterMCPExecution",
            "generation_id": "gen123",
        }

        response = handle_after_mcp_execution(event_data)

        assert response == {"decision": "allow"}

    def test_session_start_returns_allow(self, tmp_path, monkeypatch):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()

        def mock_cache_dir():
            return cache_dir

        monkeypatch.setattr(
            "ggshield.verticals.mcp_monitor.tool_mapping.get_mcp_cache_dir",
            mock_cache_dir,
        )
        monkeypatch.setattr(
            "ggshield.verticals.mcp_monitor.identity.get_mcp_cache_dir", mock_cache_dir
        )

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()

            event_data = {
                "workspace_roots": [str(tmp_path)],
                "hook_event_name": "sessionStart",
            }

            response = handle_session_start(event_data)

        assert response == {"decision": "allow"}


class TestProcessMcpMonitorEvent:
    def test_routes_to_correct_handler(self, tmp_path, monkeypatch):
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
            "ggshield.verticals.mcp_monitor.activity.get_mcp_output_dir",
            mock_output_dir,
        )

        event_data = {
            "workspace_roots": [str(tmp_path)],
            "tool_name": "test_tool",
            "hook_event_name": "beforeMCPExecution",
            "generation_id": "gen123",
        }

        response = process_mcp_monitor_event(event_data)

        assert response == {"decision": "allow"}

    def test_raises_for_missing_event_name(self):
        with pytest.raises(ValueError, match="Missing 'hook_event_name'"):
            process_mcp_monitor_event({})

    def test_raises_for_unsupported_event_type(self):
        with pytest.raises(ValueError, match="Unsupported event type"):
            process_mcp_monitor_event({"hook_event_name": "unknownEvent"})

    def test_raises_for_unhandled_event_type(self):
        with pytest.raises(ValueError, match="Event type not handled"):
            process_mcp_monitor_event({"hook_event_name": "beforeShellExecution"})


class TestMcpMonitorCmd:
    def test_returns_error_on_empty_stdin(self):
        runner = CliRunner()

        result = runner.invoke(mcp_monitor_cmd, input="")

        assert result.exit_code == 1
        assert "No input received on stdin" in result.output

    def test_returns_error_on_invalid_json(self):
        runner = CliRunner()

        result = runner.invoke(mcp_monitor_cmd, input="not json")

        assert result.exit_code == 1
        assert "Failed to parse JSON" in result.output

    def test_returns_error_on_missing_event_name(self):
        runner = CliRunner()

        result = runner.invoke(mcp_monitor_cmd, input="{}")

        assert result.exit_code == 1
        assert "Missing 'hook_event_name'" in result.output

    def test_successful_before_mcp_execution(self, tmp_path, monkeypatch):
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
            "ggshield.verticals.mcp_monitor.activity.get_mcp_output_dir",
            mock_output_dir,
        )

        runner = CliRunner()
        event_data = {
            "workspace_roots": [str(tmp_path)],
            "tool_name": "test_tool",
            "hook_event_name": "beforeMCPExecution",
            "generation_id": "gen123",
        }

        result = runner.invoke(mcp_monitor_cmd, input=json.dumps(event_data))

        assert result.exit_code == 0
        response = json.loads(result.output.strip())
        assert response == {"decision": "allow"}
