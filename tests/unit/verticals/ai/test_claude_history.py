from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from pygitguardian.models import AIDiscovery, MCPConfiguration, MCPServer, UserInfo

from ggshield.verticals.ai.agents.claude_code import Claude


def _entry(**overrides) -> dict:
    base = {
        "type": "assistant",
        "sessionId": "session-1",
        "cwd": "/home/u/repo",
        "isSidechain": False,
        "timestamp": "2026-04-01T09:00:00.000Z",
        "message": {
            "model": "claude-opus-4-7",
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_AAA",
                    "name": "mcp__linear__get_issue",
                    "input": {"id": "NHI-1"},
                }
            ],
        },
    }
    base.update(overrides)
    return base


@pytest.fixture
def empty_ai_config() -> AIDiscovery:
    return AIDiscovery(
        user=UserInfo(hostname="h", username="u", machine_id="m"),
        servers=[],
        discovery_duration=0.0,
    )


class TestClaudeParseHistoryEntry:
    def test_extracts_mcp_tool_use(self, empty_ai_config) -> None:
        events = list(Claude()._parse_history_entry(_entry(), empty_ai_config))
        assert len(events) == 1
        ev = events[0]
        assert ev.tool == "get_issue"
        assert ev.server == "linear"
        assert ev.agent == "claude-code"
        assert ev.model == "claude-opus-4-7"
        assert ev.cwd == "/home/u/repo"
        assert ev.timestamp == datetime(2026, 4, 1, 9, 0, tzinfo=timezone.utc)
        assert ev.input == {"id": "NHI-1"}

    def test_ignores_non_mcp_tools(self, empty_ai_config) -> None:
        entry = _entry(
            message={
                "model": "claude-opus-4-7",
                "content": [
                    {"type": "tool_use", "id": "toolu_X", "name": "Read", "input": {}}
                ],
            }
        )
        assert list(Claude()._parse_history_entry(entry, empty_ai_config)) == []

    def test_ignores_sidechain_entries(self, empty_ai_config) -> None:
        entry = _entry(isSidechain=True)
        assert list(Claude()._parse_history_entry(entry, empty_ai_config)) == []

    def test_skips_non_dict_entries(self, empty_ai_config) -> None:
        assert list(Claude()._parse_history_entry("not-a-dict", empty_ai_config)) == []

    def test_resolves_server_display_name_from_discovery(self) -> None:
        config = AIDiscovery(
            user=UserInfo(hostname="h", username="u", machine_id="m"),
            servers=[
                MCPServer(
                    name="LinearDisplay",
                    configurations=[
                        MCPConfiguration(
                            name="linear",
                            agent="claude-code",
                            scope=MCPConfiguration.Scope.USER,
                            transport=MCPConfiguration.Transport.STDIO,
                            project=None,
                        )
                    ],
                ),
            ],
            discovery_duration=0.0,
        )
        events = list(Claude()._parse_history_entry(_entry(), config))
        assert events[0].server == "LinearDisplay"


class TestClaudeHistoryFiles:
    def test_globs_jsonl_under_projects_dir(self, tmp_path: Path) -> None:
        (tmp_path / ".claude" / "projects" / "p1").mkdir(parents=True)
        (tmp_path / ".claude" / "projects" / "p1" / "s1.jsonl").write_text("{}\n")
        (tmp_path / ".claude" / "projects" / "p2").mkdir(parents=True)
        (tmp_path / ".claude" / "projects" / "p2" / "s2.jsonl").write_text("{}\n")
        # Should ignore non-jsonl
        (tmp_path / ".claude" / "projects" / "p2" / "ignore.txt").write_text("x")

        with patch(
            "ggshield.verticals.ai.agents.claude_code.get_user_home_dir",
            return_value=tmp_path,
        ):
            files = sorted(Claude()._history_files())

        assert [f.name for f in files] == ["s1.jsonl", "s2.jsonl"]
