from unittest.mock import MagicMock, patch

from ggshield.verticals.ai.raw_history.models import RawHistoryEvent
from ggshield.verticals.ai.raw_history.orchestrator import (
    BATCH_SIZE,
    collect_raw_history,
    send_raw_agent_history_batch,
)


def test_send_raw_agent_history_batch_serialises_and_calls_client() -> None:
    client = MagicMock()
    client.send_raw_agent_history.return_value = MagicMock(
        success=True, ingested=2, duplicates=0
    )
    events = [
        RawHistoryEvent(
            agent_name="claude-code",
            source_kind="session_transcript",
            source_path="projects/-p/bc7b2260.jsonl",
            record_offset="0",
            content='{"x": 1}',
        ),
        RawHistoryEvent(
            agent_name="cursor",
            source_kind="composer_bubble",
            source_path="globalStorage/state.vscdb",
            record_offset="bubbleId:abc:xyz",
            content='{"key": "bubbleId:abc:xyz", "value": "{"y": 2}"}',
        ),
    ]
    result = send_raw_agent_history_batch(client, events)
    client.send_raw_agent_history.assert_called_once_with(
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


def test_send_raw_agent_history_batch_empty_list_short_circuits() -> None:
    client = MagicMock()
    result = send_raw_agent_history_batch(client, [])
    client.send_raw_agent_history.assert_not_called()
    assert result.ingested == 0


def _make_agent(name: str, events: list[RawHistoryEvent]) -> MagicMock:
    a = MagicMock()
    a.name = name
    a.iter_raw_history_events.return_value = iter(events)
    return a


def _event(agent_name: str, i: int) -> RawHistoryEvent:
    return RawHistoryEvent(
        agent_name=agent_name,
        source_kind="k",
        source_path="f.jsonl",
        record_offset=str(i),
        content=f'{{"i": {i}}}',
    )


def test_collect_raw_history_batches_in_chunks_of_batch_size() -> None:
    """An agent yielding more than BATCH_SIZE events triggers multiple sends."""
    events = [_event("a", i) for i in range(BATCH_SIZE + 3)]
    agent = _make_agent("a", events)
    client = MagicMock()
    client.send_raw_agent_history.return_value = MagicMock(
        success=True, ingested=BATCH_SIZE, duplicates=0
    )

    with patch("ggshield.verticals.ai.raw_history.orchestrator.AGENTS", {"a": agent}):
        report = collect_raw_history(client)

    assert client.send_raw_agent_history.call_count == 2
    assert report.parsed == BATCH_SIZE + 3


def test_collect_raw_history_aggregates_per_agent_counts() -> None:
    events_a = [_event("a", 1)]
    events_b = [_event("b", 2)]
    client = MagicMock()
    client.send_raw_agent_history.return_value = MagicMock(
        success=True, ingested=2, duplicates=0
    )

    with patch(
        "ggshield.verticals.ai.raw_history.orchestrator.AGENTS",
        {
            "a": _make_agent("a", events_a),
            "b": _make_agent("b", events_b),
        },
    ):
        report = collect_raw_history(client)

    assert report.parsed == 2
    assert report.ingested == 2


def test_collect_raw_history_handles_empty_agents() -> None:
    client = MagicMock()
    with patch(
        "ggshield.verticals.ai.raw_history.orchestrator.AGENTS",
        {
            "a": _make_agent("a", []),
        },
    ):
        report = collect_raw_history(client)
    client.send_raw_agent_history.assert_not_called()
    assert report.parsed == 0
