import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from pygitguardian.models import AIDiscovery, MCPConfiguration, MCPServer, UserInfo

from ggshield.verticals.ai.agents.copilot import Copilot


def _session_start(cwd: str = "/repo", session_id: str = "sess-1") -> str:
    return json.dumps(
        {
            "type": "session.start",
            "data": {
                "sessionId": session_id,
                "context": {"cwd": cwd},
            },
            "id": "evt-start",
            "timestamp": "2026-05-18T14:09:37.678Z",
        }
    )


def _tool_execution_start(
    tool_call_id: str = "call-1",
    mcp_server_name: str = "github-mcp-server",
    mcp_tool_name: str = "get_file_contents",
    arguments=None,
    timestamp: str = "2026-05-18T14:10:46.052Z",
) -> str:
    data: dict = {
        "toolCallId": tool_call_id,
        "toolName": f"{mcp_server_name}-{mcp_tool_name}",
        "arguments": arguments if arguments is not None else {"owner": "GitGuardian"},
        "turnId": "0",
    }
    if mcp_server_name:
        data["mcpServerName"] = mcp_server_name
    if mcp_tool_name:
        data["mcpToolName"] = mcp_tool_name
    return json.dumps(
        {
            "type": "tool.execution_start",
            "data": data,
            "id": f"evt-{tool_call_id}",
            "timestamp": timestamp,
        }
    )


def _seed_session(tmp_path: Path, lines: list, session_id: str = "sess-1") -> Path:
    session_dir = tmp_path / ".copilot" / "session-state" / session_id
    session_dir.mkdir(parents=True)
    events = session_dir / "events.jsonl"
    events.write_text("\n".join(lines) + "\n")
    return events


@pytest.fixture
def empty_ai_config() -> AIDiscovery:
    return AIDiscovery(
        user=UserInfo(hostname="h", username="u", machine_id="m"),
        servers=[],
        discovery_duration=0.0,
    )


class TestCopilotIterHistoryEvents:
    def test_extracts_mcp_call(self, tmp_path: Path, empty_ai_config) -> None:
        _seed_session(
            tmp_path,
            [
                _session_start(cwd="/repo"),
                _tool_execution_start(
                    tool_call_id="call_abc",
                    mcp_server_name="github-mcp-server",
                    mcp_tool_name="get_file_contents",
                    arguments={"owner": "GitGuardian", "repo": "ggshield"},
                    timestamp="2026-05-18T14:10:46.052Z",
                ),
            ],
        )

        with patch(
            "ggshield.verticals.ai.agents.copilot.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(Copilot().iter_history_events(empty_ai_config))

        assert len(events) == 1
        ev = events[0]
        assert ev.tool == "get_file_contents"
        assert ev.server == "github-mcp-server"
        assert ev.agent == "copilot"
        assert ev.cwd == "/repo"
        assert ev.timestamp == datetime(
            2026, 5, 18, 14, 10, 46, 52000, tzinfo=timezone.utc
        )
        assert ev.input == {"owner": "GitGuardian", "repo": "ggshield"}

    def test_skips_non_mcp_tool_calls(self, tmp_path: Path, empty_ai_config) -> None:
        """``tool.execution_start`` events without ``mcpServerName`` are not MCP calls."""
        builtin = json.dumps(
            {
                "type": "tool.execution_start",
                "data": {
                    "toolCallId": "call_builtin",
                    "toolName": "report_intent",
                    "arguments": {"intent": "Searching"},
                    "turnId": "0",
                },
                "id": "evt-builtin",
                "timestamp": "2026-05-18T14:10:46.052Z",
            }
        )
        _seed_session(tmp_path, [_session_start(), builtin])

        with patch(
            "ggshield.verticals.ai.agents.copilot.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(Copilot().iter_history_events(empty_ai_config))

        assert events == []

    def test_drops_event_with_unparseable_timestamp(
        self, tmp_path: Path, empty_ai_config
    ) -> None:
        _seed_session(
            tmp_path,
            [
                _session_start(),
                _tool_execution_start(timestamp="not-a-date"),
            ],
        )

        with patch(
            "ggshield.verticals.ai.agents.copilot.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(Copilot().iter_history_events(empty_ai_config))

        assert events == []

    def test_resolves_server_name_via_configuration(self, tmp_path: Path) -> None:
        """``mcpServerName`` matches ``MCPConfiguration.name`` byte-for-byte."""
        _seed_session(
            tmp_path,
            [
                _session_start(),
                _tool_execution_start(mcp_server_name="github-mcp-server"),
            ],
        )

        config = AIDiscovery(
            user=UserInfo(hostname="h", username="u", machine_id="m"),
            servers=[
                MCPServer(
                    name="GitHub",
                    configurations=[
                        MCPConfiguration(
                            name="github-mcp-server",
                            agent="copilot",
                            scope=MCPConfiguration.Scope.USER,
                            transport=MCPConfiguration.Transport.STDIO,
                            project=None,
                        )
                    ],
                )
            ],
            discovery_duration=0.0,
        )

        with patch(
            "ggshield.verticals.ai.agents.copilot.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(Copilot().iter_history_events(config))

        assert events[0].server == "GitHub"

    def test_walks_multiple_sessions(self, tmp_path: Path, empty_ai_config) -> None:
        _seed_session(
            tmp_path,
            [_session_start(cwd="/repo-a"), _tool_execution_start(tool_call_id="a")],
            session_id="sess-a",
        )
        _seed_session(
            tmp_path,
            [_session_start(cwd="/repo-b"), _tool_execution_start(tool_call_id="b")],
            session_id="sess-b",
        )

        with patch(
            "ggshield.verticals.ai.agents.copilot.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(Copilot().iter_history_events(empty_ai_config))

        assert {ev.cwd for ev in events} == {"/repo-a", "/repo-b"}

    def test_missing_history_root_yields_nothing(
        self, tmp_path: Path, empty_ai_config
    ) -> None:
        """A user who has never run Copilot CLI has no ``~/.copilot/session-state``."""
        with patch(
            "ggshield.verticals.ai.agents.copilot.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(Copilot().iter_history_events(empty_ai_config))

        assert events == []

    def test_session_without_events_file_is_skipped(
        self, tmp_path: Path, empty_ai_config
    ) -> None:
        (tmp_path / ".copilot" / "session-state" / "empty").mkdir(parents=True)

        with patch(
            "ggshield.verticals.ai.agents.copilot.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(Copilot().iter_history_events(empty_ai_config))

        assert events == []
