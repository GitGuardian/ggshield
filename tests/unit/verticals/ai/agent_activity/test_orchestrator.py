from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import requests
from pygitguardian.models import Detail

from ggshield.verticals.ai.agent_activity.cursors import (
    NOTHING,
    CursorStore,
    scope_for,
)
from ggshield.verticals.ai.agent_activity.models import AgentActivityEvent
from ggshield.verticals.ai.agent_activity.orchestrator import (
    BATCH_SIZE,
    MAX_BATCH_BYTES,
    collect_agent_activity,
    send_agent_activity_batch,
)


def test_send_agent_activity_batch_serialises_and_calls_client() -> None:
    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(
        success=True, ingested=2, duplicates=0
    )
    events = [
        AgentActivityEvent(
            agent_name="claude-code",
            source_kind="session_transcript",
            source_path="projects/-p/bc7b2260.jsonl",
            record_offset="0",
            content='{"x": 1}',
        ),
        AgentActivityEvent(
            agent_name="cursor",
            source_kind="composer_bubble",
            source_path="globalStorage/state.vscdb",
            record_offset="bubbleId:abc:xyz",
            content='{"key": "bubbleId:abc:xyz", "value": "{"y": 2}"}',
        ),
    ]
    result = send_agent_activity_batch(client, events)
    client.send_agent_activity.assert_called_once_with(
        [
            {
                "agent_name": "claude-code",
                "source_kind": "session_transcript",
                "source_path": "projects/-p/bc7b2260.jsonl",
                "record_offset": "0",
                "content": '{"x": 1}',
            },
            {
                "agent_name": "cursor",
                "source_kind": "composer_bubble",
                "source_path": "globalStorage/state.vscdb",
                "record_offset": "bubbleId:abc:xyz",
                "content": '{"key": "bubbleId:abc:xyz", "value": "{"y": 2}"}',
            },
        ]
    )
    assert result.ingested == 2


def test_send_agent_activity_batch_empty_list_short_circuits() -> None:
    client = MagicMock()
    result = send_agent_activity_batch(client, [])
    client.send_agent_activity.assert_not_called()
    assert result.ingested == 0


def test_send_agent_activity_batch_treats_detail_as_failure() -> None:
    """An API error (Detail) is reported as a failed batch, not an ingest."""
    client = MagicMock()
    client.send_agent_activity.return_value = Detail("boom", status_code=500)
    result = send_agent_activity_batch(client, [_event("a", 1)])
    assert result.success is False
    assert result.ingested == 0
    assert result.duplicates == 0


def test_collect_agent_activity_counts_detail_response_as_failed_batch() -> None:
    client = MagicMock()
    client.send_agent_activity.return_value = Detail("boom", status_code=500)
    with patch(
        "ggshield.verticals.ai.agents.AGENTS",
        {"a": _make_agent("a", [_event("a", 1)])},
    ):
        report = collect_agent_activity(client)
    assert report.parsed == 1
    assert report.ingested == 0
    assert report.failed_batches == 1


def _make_agent(name: str, events: list[AgentActivityEvent]) -> MagicMock:
    a = MagicMock()
    a.name = name
    # No resumable sources by default: these tests focus on batching/counts, not
    # cursor behaviour (covered in test_cursors.py and the resume tests below).
    a.agent_activity_sources = []
    a.iter_agent_activity_events.return_value = iter(events)
    return a


def _event(agent_name: str, i: int) -> AgentActivityEvent:
    return AgentActivityEvent(
        agent_name=agent_name,
        source_kind="k",
        source_path="f.jsonl",
        record_offset=str(i),
        content=f'{{"i": {i}}}',
    )


def test_collect_agent_activity_batches_in_chunks_of_batch_size() -> None:
    """An agent yielding more than BATCH_SIZE events triggers multiple sends."""
    events = [_event("a", i) for i in range(BATCH_SIZE + 3)]
    agent = _make_agent("a", events)
    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(
        success=True, ingested=BATCH_SIZE, duplicates=0
    )

    with patch("ggshield.verticals.ai.agents.AGENTS", {"a": agent}):
        report = collect_agent_activity(client)

    assert client.send_agent_activity.call_count == 2
    assert report.parsed == BATCH_SIZE + 3


def test_collect_agent_activity_aggregates_per_agent_counts() -> None:
    events_a = [_event("a", 1)]
    events_b = [_event("b", 2)]
    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(
        success=True, ingested=2, duplicates=0
    )

    with patch(
        "ggshield.verticals.ai.agents.AGENTS",
        {
            "a": _make_agent("a", events_a),
            "b": _make_agent("b", events_b),
        },
    ):
        report = collect_agent_activity(client)

    assert report.parsed == 2
    assert report.ingested == 2


def test_collect_agent_activity_handles_empty_agents() -> None:
    client = MagicMock()
    with patch(
        "ggshield.verticals.ai.agents.AGENTS",
        {
            "a": _make_agent("a", []),
        },
    ):
        report = collect_agent_activity(client)
    client.send_agent_activity.assert_not_called()
    assert report.parsed == 0


def test_collect_agent_activity_flushes_on_byte_threshold() -> None:
    """Large records flush on the byte budget before reaching BATCH_SIZE count."""
    big = "x" * (MAX_BATCH_BYTES + 1)  # each event alone exceeds the budget
    events = [
        AgentActivityEvent(
            agent_name="a",
            source_kind="k",
            source_path="f",
            record_offset=str(i),
            content=big,
        )
        for i in range(3)
    ]
    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(ingested=1, duplicates=0)

    with patch("ggshield.verticals.ai.agents.AGENTS", {"a": _make_agent("a", events)}):
        report = collect_agent_activity(client)

    # 3 oversized events => 3 separate sends, none waiting for the 500 count.
    assert client.send_agent_activity.call_count == 3
    assert report.parsed == 3


def test_collect_agent_activity_counts_network_error_as_failed_batch() -> None:
    """A network error while sending a batch is counted as a failed batch."""
    client = MagicMock()
    client.send_agent_activity.side_effect = requests.exceptions.ConnectionError("down")
    with patch(
        "ggshield.verticals.ai.agents.AGENTS",
        {"a": _make_agent("a", [_event("a", 1)])},
    ):
        report = collect_agent_activity(client)

    assert report.parsed == 1
    assert report.ingested == 0
    assert report.failed_batches == 1


# --- cursor / resume behaviour -------------------------------------------------


def _resumable_agent(
    name: str, kind: str, events: list[AgentActivityEvent]
) -> MagicMock:
    a = MagicMock()
    a.name = name
    a.agent_activity_sources = [SimpleNamespace(kind=kind, supports_resume=True)]
    a.iter_agent_activity_events.return_value = iter(events)
    return a


def _rec(
    agent_name: str, kind: str, source_path: str, index: int
) -> AgentActivityEvent:
    return AgentActivityEvent(
        agent_name=agent_name,
        source_kind=kind,
        source_path=source_path,
        record_offset=str(index),
        content="{}",
    )


def test_cursor_advances_on_successful_ingest() -> None:
    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(
        success=True, ingested=3, duplicates=0
    )
    events = [_rec("claude-code", "session_transcript", "p.jsonl", i) for i in range(3)]
    agent = _resumable_agent("claude-code", "session_transcript", events)

    with patch("ggshield.verticals.ai.agents.AGENTS", {"a": agent}):
        collect_agent_activity(client)

    scope = scope_for(client)
    store = CursorStore.load()
    assert store.get(scope, "claude-code", "session_transcript", "p.jsonl") == 2


def test_cursor_not_advanced_when_batch_fails() -> None:
    client = MagicMock()
    client.send_agent_activity.return_value = Detail("boom", status_code=500)
    events = [_rec("claude-code", "session_transcript", "p.jsonl", i) for i in range(2)]
    agent = _resumable_agent("claude-code", "session_transcript", events)

    with patch("ggshield.verticals.ai.agents.AGENTS", {"a": agent}):
        report = collect_agent_activity(client)

    assert report.failed_batches == 1
    scope = scope_for(client)
    store = CursorStore.load()
    assert store.get(scope, "claude-code", "session_transcript", "p.jsonl") == NOTHING


def test_cursor_freeze_does_not_skip_gap_after_failure(monkeypatch) -> None:
    """With one record per batch: index 0 succeeds, 1 fails, 2 succeeds. The
    cursor must stay at 0 — never jump past the failed record."""
    monkeypatch.setattr(
        "ggshield.verticals.ai.agent_activity.orchestrator.BATCH_SIZE", 1
    )
    client = MagicMock()
    client.send_agent_activity.side_effect = [
        MagicMock(success=True, ingested=1, duplicates=0),
        Detail("boom", status_code=500),
        MagicMock(success=True, ingested=1, duplicates=0),
    ]
    events = [_rec("claude-code", "session_transcript", "p.jsonl", i) for i in range(3)]
    agent = _resumable_agent("claude-code", "session_transcript", events)

    with patch("ggshield.verticals.ai.agents.AGENTS", {"a": agent}):
        collect_agent_activity(client)

    scope = scope_for(client)
    store = CursorStore.load()
    assert store.get(scope, "claude-code", "session_transcript", "p.jsonl") == 0


def test_non_resumable_source_is_not_tracked() -> None:
    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(
        success=True, ingested=1, duplicates=0
    )
    agent = MagicMock()
    agent.name = "cursor"
    agent.agent_activity_sources = [
        SimpleNamespace(kind="composer_bubble", supports_resume=False)
    ]
    agent.iter_agent_activity_events.return_value = iter(
        [_rec("cursor", "composer_bubble", "state.vscdb", 0)]
    )

    with patch("ggshield.verticals.ai.agents.AGENTS", {"a": agent}):
        collect_agent_activity(client)

    scope = scope_for(client)
    store = CursorStore.load()
    assert store.get(scope, "cursor", "composer_bubble", "state.vscdb") == NOTHING


def test_collect_passes_committed_cursor_as_resume_lookup() -> None:
    """A pre-seeded cursor is handed to the agent as the resume lookup."""
    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(
        success=True, ingested=0, duplicates=0
    )
    scope = scope_for(client)
    seed = CursorStore.load()
    seed.advance(scope, "claude-code", "session_transcript", "p.jsonl", 5)
    seed.save()

    captured = {}

    def _iter(resume_for=None):
        captured["mark"] = resume_for("session_transcript", "p.jsonl")
        return iter([])

    agent = MagicMock()
    agent.name = "claude-code"
    agent.agent_activity_sources = [
        SimpleNamespace(kind="session_transcript", supports_resume=True)
    ]
    agent.iter_agent_activity_events.side_effect = _iter

    with patch("ggshield.verticals.ai.agents.AGENTS", {"a": agent}):
        collect_agent_activity(client)

    assert captured["mark"] == 5


def test_cursor_skips_record_with_non_integer_offset() -> None:
    """A resumable record whose offset is not an int is excluded from the mark."""
    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(
        success=True, ingested=1, duplicates=0
    )
    bad = AgentActivityEvent(
        agent_name="claude-code",
        source_kind="session_transcript",
        source_path="p.jsonl",
        record_offset="not-an-int",
        content="{}",
    )
    agent = _resumable_agent("claude-code", "session_transcript", [bad])

    with patch("ggshield.verticals.ai.agents.AGENTS", {"a": agent}):
        collect_agent_activity(client)

    scope = scope_for(client)
    store = CursorStore.load()
    assert store.get(scope, "claude-code", "session_transcript", "p.jsonl") == NOTHING


def test_resume_end_to_end_skips_already_shipped_records(tmp_path) -> None:
    """Full chain (real Claude source + real cursor): the second run, after one
    new line is appended, ships only that new line."""
    from ggshield.verticals.ai.agents.claude_code import Claude

    # GG_USER_HOME_DIR / GG_CACHE_DIR are redirected to tmp_path by an autouse
    # fixture, so the real source discovers this transcript and the cursor file
    # lives in the isolated cache dir.
    proj = tmp_path / "home" / ".claude" / "projects" / "-repo"
    proj.mkdir(parents=True)
    (proj / "s.jsonl").write_text('{"i": 0}\n{"i": 1}\n')

    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(
        success=True, ingested=2, duplicates=0
    )

    with patch("ggshield.verticals.ai.agents.AGENTS", {"claude": Claude()}):
        first = collect_agent_activity(client)
        assert first.parsed == 2

        (proj / "s.jsonl").write_text('{"i": 0}\n{"i": 1}\n{"i": 2}\n')
        client.send_agent_activity.reset_mock()
        client.send_agent_activity.return_value = MagicMock(
            success=True, ingested=1, duplicates=0
        )
        second = collect_agent_activity(client)

    assert second.parsed == 1  # only the newly-appended line
    payload = client.send_agent_activity.call_args.args[0]
    assert [r["record_offset"] for r in payload] == ["2"]
