import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from pygitguardian.models import AIDiscovery, MCPConfiguration, MCPServer, UserInfo

from ggshield.verticals.ai.agents.vscode import VSCode, _find_mcp_invocations


def _invocation(
    tool_call_id: str = "tc-1",
    tool_id: str = "mcp_makenotion_no_notion-search",
    server_label: str = "Notion MCP",
    label: str = "makenotion/notion-mcp-server",
    raw_input=None,
) -> dict:
    return {
        "kind": "toolInvocationSerialized",
        "source": {
            "type": "mcp",
            "serverLabel": server_label,
            "label": label,
            "collectionId": "mcp.config.usrlocal",
        },
        "toolCallId": tool_call_id,
        "toolId": tool_id,
        "isComplete": True,
        "toolSpecificData": {
            "kind": "input",
            "rawInput": raw_input if raw_input is not None else {"q": "x"},
        },
    }


def _request_line(timestamp_ms: int, response: list, request_id: str = "req-1") -> str:
    return json.dumps(
        {
            "kind": 2,
            "v": [
                {
                    "requestId": request_id,
                    "timestamp": timestamp_ms,
                    "response": response,
                }
            ],
        }
    )


@pytest.fixture
def empty_ai_config() -> AIDiscovery:
    return AIDiscovery(
        user=UserInfo(hostname="h", username="u", machine_id="m"),
        servers=[],
        discovery_duration=0.0,
    )


class TestFindMCPInvocations:
    def test_finds_nested_mcp_invocations(self) -> None:
        obj = {
            "v": [
                {"response": [_invocation("a"), {"kind": "thinking"}]},
                {"response": [_invocation("b", server_label="Other", label="other/x")]},
            ]
        }
        found = list(_find_mcp_invocations(obj))
        assert [i["toolCallId"] for i in found] == ["a", "b"]

    def test_skips_internal_tools(self) -> None:
        obj = {
            "kind": "toolInvocationSerialized",
            "source": {"type": "internal"},
            "toolCallId": "x",
        }
        assert list(_find_mcp_invocations(obj)) == []


class TestVSCodeIterHistoryEvents:
    def _seed_session(
        self, tmp_path: Path, lines: list[str], workspace_folder: str
    ) -> Path:
        workspace_hash = (
            tmp_path / ".config" / "Code" / "User" / "workspaceStorage" / "ws1"
        )
        sessions = workspace_hash / "chatSessions"
        sessions.mkdir(parents=True)
        (workspace_hash / "workspace.json").write_text(
            json.dumps({"folder": f"file://{workspace_folder}"})
        )
        session = sessions / "session.jsonl"
        session.write_text("\n".join(lines) + "\n")
        return session

    def test_extracts_mcp_calls_with_request_timestamp(
        self, tmp_path: Path, empty_ai_config
    ) -> None:
        ts_ms = 1_778_855_521_780
        line = _request_line(ts_ms, [_invocation("call-1")])
        self._seed_session(tmp_path, [line], "/repo")

        with patch(
            "ggshield.verticals.ai.agents.vscode.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(VSCode().iter_history_events(empty_ai_config))

        assert len(events) == 1
        ev = events[0]
        assert ev.tool == "no_notion-search"
        assert ev.server == "makenotion/notion-mcp-server"
        assert ev.agent == "vscode"
        assert ev.cwd == "/repo"
        assert ev.timestamp == datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        assert ev.input == {"q": "x"}

    def test_dedupes_by_tool_call_id(self, tmp_path: Path, empty_ai_config) -> None:
        """Same toolCallId across delta lines should yield exactly one event."""
        ts_ms = 1_778_855_521_780
        # First snapshot: invocation partial. Second snapshot: invocation again.
        lines = [
            _request_line(ts_ms, [_invocation("dup", raw_input={"q": "partial"})]),
            _request_line(ts_ms, [_invocation("dup", raw_input={"q": "final"})]),
        ]
        self._seed_session(tmp_path, lines, "/repo")

        with patch(
            "ggshield.verticals.ai.agents.vscode.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(VSCode().iter_history_events(empty_ai_config))

        assert len(events) == 1

    def test_bare_invocation_uses_last_request_timestamp(
        self, tmp_path: Path, empty_ai_config
    ) -> None:
        """A delta line carrying just a toolInvocation (no request envelope)
        should inherit the most-recently-seen request timestamp."""
        ts_ms = 1_778_855_521_780
        bare_line = json.dumps({"kind": 2, "v": [_invocation("bare")]})
        lines = [
            _request_line(ts_ms, []),  # establishes last_ts
            bare_line,
        ]
        self._seed_session(tmp_path, lines, "/repo")

        with patch(
            "ggshield.verticals.ai.agents.vscode.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(VSCode().iter_history_events(empty_ai_config))

        assert len(events) == 1
        assert events[0].timestamp == datetime.fromtimestamp(
            ts_ms / 1000, tz=timezone.utc
        )

    def test_uses_snapshot_request_timestamp_for_later_invocation(
        self, tmp_path: Path, empty_ai_config
    ) -> None:
        """The ``kind:0`` snapshot stores the request timestamp inside a dict
        (``v.requests[].timestamp``), not a top-level list. A later delta line
        carrying the MCP invocation must still inherit that timestamp."""
        ts_ms = 1_778_855_521_780
        snapshot = json.dumps(
            {
                "kind": 0,
                "v": {
                    "version": 3,
                    "requests": [
                        {"requestId": "req-1", "timestamp": ts_ms, "response": []}
                    ],
                },
            }
        )
        bare_line = json.dumps({"kind": 2, "v": [_invocation("late")]})
        self._seed_session(tmp_path, [snapshot, bare_line], "/repo")

        with patch(
            "ggshield.verticals.ai.agents.vscode.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(VSCode().iter_history_events(empty_ai_config))

        assert len(events) == 1
        assert events[0].timestamp == datetime.fromtimestamp(
            ts_ms / 1000, tz=timezone.utc
        )

    def test_uses_nested_tool_call_round_timestamp(
        self, tmp_path: Path, empty_ai_config
    ) -> None:
        """Some delta lines carry the timestamp nested under
        ``v.metadata.toolCallRounds[].timestamp`` rather than at the top level."""
        ts_ms = 1_778_855_521_780
        round_line = json.dumps(
            {
                "kind": 1,
                "v": {"metadata": {"toolCallRounds": [{"timestamp": ts_ms}]}},
            }
        )
        bare_line = json.dumps({"kind": 2, "v": [_invocation("nested")]})
        self._seed_session(tmp_path, [round_line, bare_line], "/repo")

        with patch(
            "ggshield.verticals.ai.agents.vscode.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(VSCode().iter_history_events(empty_ai_config))

        assert len(events) == 1
        assert events[0].timestamp == datetime.fromtimestamp(
            ts_ms / 1000, tz=timezone.utc
        )

    def test_drops_invocation_without_timestamp(
        self, tmp_path: Path, empty_ai_config
    ) -> None:
        """If no request snapshot has been seen yet, there's no timestamp to attach."""
        bare_line = json.dumps({"kind": 2, "v": [_invocation("orphan")]})
        self._seed_session(tmp_path, [bare_line], "/repo")

        with patch(
            "ggshield.verticals.ai.agents.vscode.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(VSCode().iter_history_events(empty_ai_config))

        assert events == []

    def test_resolves_server_name_via_configuration(self, tmp_path: Path) -> None:
        """``source.label`` matches ``MCPConfiguration.name`` byte-for-byte."""
        ts_ms = 1_778_855_521_780
        line = _request_line(ts_ms, [_invocation("c")])
        self._seed_session(tmp_path, [line], "/repo")

        config = AIDiscovery(
            user=UserInfo(hostname="h", username="u", machine_id="m"),
            servers=[
                MCPServer(
                    name="Notion",
                    configurations=[
                        MCPConfiguration(
                            name="makenotion/notion-mcp-server",
                            agent="vscode",
                            scope=MCPConfiguration.Scope.USER,
                            transport=MCPConfiguration.Transport.HTTP,
                            project=None,
                        )
                    ],
                )
            ],
            discovery_duration=0.0,
        )

        with patch(
            "ggshield.verticals.ai.agents.vscode.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(VSCode().iter_history_events(config))

        assert events[0].server == "Notion"
        assert events[0].tool == "notion-search"

    def test_ignores_legacy_json_sessions(
        self, tmp_path: Path, empty_ai_config
    ) -> None:
        workspace_hash = (
            tmp_path / ".config" / "Code" / "User" / "workspaceStorage" / "ws1"
        )
        sessions = workspace_hash / "chatSessions"
        sessions.mkdir(parents=True)
        (workspace_hash / "workspace.json").write_text(
            json.dumps({"folder": "file:///repo"})
        )
        (sessions / "legacy.json").write_text(json.dumps({"requests": []}))

        with patch(
            "ggshield.verticals.ai.agents.vscode.get_user_home_dir",
            return_value=tmp_path,
        ):
            events = list(VSCode().iter_history_events(empty_ai_config))

        assert events == []
