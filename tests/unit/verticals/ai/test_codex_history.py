import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from pygitguardian.models import AIDiscovery, MCPConfiguration, MCPServer, UserInfo

from ggshield.verticals.ai.agents.codex import Codex


def _function_call_entry(
    *,
    name: str = "get_issue",
    namespace: str = "mcp__linear__",
    arguments: str = '{"id": "NHI-1"}',
    timestamp: str = "2026-04-01T09:00:00.000Z",
) -> dict:
    """Build a Codex JSONL response_item line carrying an MCP function_call."""
    return {
        "timestamp": timestamp,
        "type": "response_item",
        "payload": {
            "type": "function_call",
            "name": name,
            "namespace": namespace,
            "arguments": arguments,
            "call_id": "call_AAA",
        },
    }


def _session_meta(cwd: str = "/home/u/repo") -> dict:
    return {
        "timestamp": "2026-04-01T08:55:00.000Z",
        "type": "session_meta",
        "payload": {"id": "sess-1", "cwd": cwd, "cli_version": "0.130.0"},
    }


def _turn_context(cwd: str = "/home/u/repo", model: str = "gpt-5.5") -> dict:
    return {
        "timestamp": "2026-04-01T08:56:00.000Z",
        "type": "turn_context",
        "payload": {"turn_id": "turn-1", "cwd": cwd, "model": model},
    }


def _write_session(path: Path, entries: list[dict]) -> None:
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")


@pytest.fixture
def empty_ai_config() -> AIDiscovery:
    return AIDiscovery(
        user=UserInfo(hostname="h", username="u", machine_id="m"),
        servers=[],
        discovery_duration=0.0,
    )


class TestCodexParseSessionFile:
    def test_extracts_mcp_tool_use(self, tmp_path: Path, empty_ai_config) -> None:
        path = tmp_path / "rollout.jsonl"
        _write_session(
            path,
            [
                _session_meta(),
                _turn_context(model="gpt-5.5"),
                _function_call_entry(),
            ],
        )

        events = list(Codex()._parse_session_file(path, empty_ai_config))

        assert len(events) == 1
        ev = events[0]
        assert ev.tool == "get_issue"
        assert ev.server == "linear"
        assert ev.agent == "codex"
        assert ev.model == "gpt-5.5"
        assert ev.cwd == "/home/u/repo"
        assert ev.input == {"id": "NHI-1"}
        assert ev.timestamp == datetime(2026, 4, 1, 9, 0, tzinfo=timezone.utc)

    def test_ignores_non_mcp_function_calls(
        self, tmp_path: Path, empty_ai_config
    ) -> None:
        path = tmp_path / "rollout.jsonl"
        _write_session(
            path,
            [
                _session_meta(),
                _turn_context(),
                # Built-in shell tool: no namespace.
                {
                    "timestamp": "2026-04-01T09:00:01.000Z",
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "name": "exec_command",
                        "arguments": '{"cmd": "ls"}',
                        "call_id": "x",
                    },
                },
                # A non-function_call response_item.
                {
                    "timestamp": "2026-04-01T09:00:02.000Z",
                    "type": "response_item",
                    "payload": {"type": "message", "role": "assistant"},
                },
            ],
        )
        assert list(Codex()._parse_session_file(path, empty_ai_config)) == []

    def test_tracks_cwd_and_model_across_turns(
        self, tmp_path: Path, empty_ai_config
    ) -> None:
        path = tmp_path / "rollout.jsonl"
        _write_session(
            path,
            [
                _session_meta(cwd="/home/u/initial"),
                _turn_context(cwd="/home/u/turn1", model="gpt-5.5"),
                _function_call_entry(timestamp="2026-04-01T09:00:01.000Z"),
                _turn_context(cwd="/home/u/turn2", model="gpt-5.6"),
                _function_call_entry(timestamp="2026-04-01T09:00:02.000Z"),
            ],
        )

        events = list(Codex()._parse_session_file(path, empty_ai_config))

        assert [(e.cwd, e.model) for e in events] == [
            ("/home/u/turn1", "gpt-5.5"),
            ("/home/u/turn2", "gpt-5.6"),
        ]

    def test_resolves_server_display_name_from_discovery(self, tmp_path: Path) -> None:
        config = AIDiscovery(
            user=UserInfo(hostname="h", username="u", machine_id="m"),
            servers=[
                MCPServer(
                    name="LinearDisplay",
                    configurations=[
                        MCPConfiguration(
                            name="linear",
                            agent="codex",
                            scope=MCPConfiguration.Scope.USER,
                            transport=MCPConfiguration.Transport.HTTP,
                            project=None,
                        )
                    ],
                ),
            ],
            discovery_duration=0.0,
        )
        path = tmp_path / "rollout.jsonl"
        _write_session(path, [_session_meta(), _turn_context(), _function_call_entry()])

        events = list(Codex()._parse_session_file(path, config))

        assert events[0].server == "LinearDisplay"


class TestCodexHistoryFiles:
    def test_globs_rollouts_under_dated_dirs(self, tmp_path: Path) -> None:
        sessions = tmp_path / ".codex" / "sessions"
        (sessions / "2026" / "04" / "01").mkdir(parents=True)
        (sessions / "2026" / "04" / "01" / "rollout-1.jsonl").write_text("{}\n")
        (sessions / "2026" / "04" / "02").mkdir(parents=True)
        (sessions / "2026" / "04" / "02" / "rollout-2.jsonl").write_text("{}\n")
        # Wrong depth — should be ignored.
        (sessions / "loose.jsonl").write_text("{}\n")
        # Wrong prefix — should be ignored.
        (sessions / "2026" / "04" / "02" / "other.jsonl").write_text("{}\n")

        with patch(
            "ggshield.verticals.ai.agents.codex.get_user_home_dir",
            return_value=tmp_path,
        ):
            files = sorted(Codex()._history_files())

        assert [f.name for f in files] == ["rollout-1.jsonl", "rollout-2.jsonl"]
