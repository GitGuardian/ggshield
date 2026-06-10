import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pygitguardian.models import AIDiscovery, MCPActivityBulkResponse, UserInfo

from ggshield.verticals.ai.history import backfill_mcp_history


def _make_discovery() -> AIDiscovery:
    return AIDiscovery(
        user=UserInfo(hostname="h", username="u", machine_id="m"),
        servers=[],
        discovery_duration=0.0,
    )


def _claude_transcript_dir(tmp_path: Path) -> Path:
    p = tmp_path / ".claude" / "projects" / "myrepo"
    p.mkdir(parents=True)
    return p


def _mcp_line(ts: str = "2026-04-01T09:00:00.000Z") -> str:
    return (
        json.dumps(
            {
                "type": "assistant",
                "sessionId": "s1",
                "cwd": "/repo",
                "isSidechain": False,
                "timestamp": ts,
                "message": {
                    "model": "claude-opus-4-7",
                    "content": [
                        {
                            "type": "tool_use",
                            "name": "mcp__linear__get_issue",
                            "input": {},
                        }
                    ],
                },
            }
        )
        + "\n"
    )


class TestBackfillMCPHistory:
    @pytest.fixture(autouse=True)
    def _patch_home(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "ggshield.verticals.ai.agents.claude_code.get_user_home_dir",
            lambda: tmp_path,
        )

    def test_uploads_all_events(self, tmp_path) -> None:
        session = _claude_transcript_dir(tmp_path) / "session1.jsonl"
        session.write_text(_mcp_line() + _mcp_line())

        client = MagicMock()
        client.log_mcp_activities_bulk.return_value = MCPActivityBulkResponse(
            ingested=2, duplicates=0, skipped=0
        )

        report = backfill_mcp_history(client, _make_discovery())

        assert client.log_mcp_activities_bulk.call_count == 1
        sent = client.log_mcp_activities_bulk.call_args.args[0]
        assert len(sent) == 2
        assert report.parsed == 2
        assert report.ingested == 2
        assert report.duplicates == 0
        assert report.skipped == 0

    def test_runs_every_time(self, tmp_path) -> None:
        """No cache: each invocation re-walks transcripts and re-sends events."""
        session = _claude_transcript_dir(tmp_path) / "session1.jsonl"
        session.write_text(_mcp_line())

        client = MagicMock()
        client.log_mcp_activities_bulk.return_value = MCPActivityBulkResponse(
            ingested=0, duplicates=1, skipped=0
        )

        first = backfill_mcp_history(client, _make_discovery())
        second = backfill_mcp_history(client, _make_discovery())

        assert client.log_mcp_activities_bulk.call_count == 2
        assert first.parsed == 1
        assert second.parsed == 1

    def test_upload_failure_reports_error(self, tmp_path) -> None:
        session = _claude_transcript_dir(tmp_path) / "session1.jsonl"
        session.write_text(_mcp_line())

        client = MagicMock()
        client.log_mcp_activities_bulk.side_effect = RuntimeError("network down")

        report = backfill_mcp_history(client, _make_discovery())
        assert report.ingested == 0
        assert report.error is not None
