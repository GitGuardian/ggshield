from unittest.mock import MagicMock

import requests
from pygitguardian.models import Detail

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
        ],
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
    report = collect_agent_activity(client, [_make_agent("a", [_event("a", 1)])])
    assert report.parsed == 1
    assert report.ingested == 0
    assert report.failed_batches == 1


def _make_agent(name: str, events: list[AgentActivityEvent]) -> MagicMock:
    a = MagicMock()
    a.name = name
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

    report = collect_agent_activity(client, [agent])

    assert client.send_agent_activity.call_count == 2
    assert report.parsed == BATCH_SIZE + 3


def test_collect_agent_activity_aggregates_per_agent_counts() -> None:
    events_a = [_event("a", 1)]
    events_b = [_event("b", 2)]
    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(
        success=True, ingested=2, duplicates=0
    )

    report = collect_agent_activity(
        client, [_make_agent("a", events_a), _make_agent("b", events_b)]
    )

    assert report.parsed == 2
    assert report.ingested == 2


def test_collect_agent_activity_handles_empty_agents() -> None:
    client = MagicMock()
    report = collect_agent_activity(client, [_make_agent("a", [])])
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

    report = collect_agent_activity(client, [_make_agent("a", events)])

    # 3 oversized events => 3 separate sends, none waiting for the 500 count.
    assert client.send_agent_activity.call_count == 3
    assert report.parsed == 3


def test_collect_agent_activity_counts_network_error_as_failed_batch() -> None:
    """A network error while sending a batch is counted as a failed batch."""
    client = MagicMock()
    client.send_agent_activity.side_effect = requests.exceptions.ConnectionError("down")
    report = collect_agent_activity(client, [_make_agent("a", [_event("a", 1)])])

    assert report.parsed == 1
    assert report.ingested == 0
    assert report.failed_batches == 1
