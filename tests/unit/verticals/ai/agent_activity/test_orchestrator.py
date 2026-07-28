from unittest.mock import MagicMock

import pytest
import requests
from pygitguardian.models import Detail, UserInfo

from ggshield.verticals.ai.agent_activity import orchestrator
from ggshield.verticals.ai.agent_activity.models import AgentActivityEvent
from ggshield.verticals.ai.agent_activity.orchestrator import (
    collect_agent_activity,
    send_agent_activity_batch,
)


_USER = UserInfo(hostname="dev-laptop", username="dev", machine_id="machine-001")


def test_send_agent_activity_batch_serialises_and_calls_client() -> None:
    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(
        success=True, ingested=2, dropped=0
    )
    events = [
        AgentActivityEvent(
            agent_name="claude-code",
            source_kind="5_session_transcript",
            source_path="projects/-p/bc7b2260.jsonl",
            record_offset="0000000",
            content='{"x": 1}',
        ),
        AgentActivityEvent(
            agent_name="cursor",
            source_kind="6_composer_bubble",
            source_path="globalStorage/state.vscdb",
            record_offset="bubbleId:abc:xyz",
            content='{"key": "bubbleId:abc:xyz", "value": "{"y": 2}"}',
        ),
    ]
    result = send_agent_activity_batch(client, events, _USER)
    client.send_agent_activity.assert_called_once_with(
        [
            {
                "agent_name": "claude-code",
                "source_kind": "5_session_transcript",
                "source_path": "projects/-p/bc7b2260.jsonl",
                "record_offset": "0000000",
                "content": '{"x": 1}',
            },
            {
                "agent_name": "cursor",
                "source_kind": "6_composer_bubble",
                "source_path": "globalStorage/state.vscdb",
                "record_offset": "bubbleId:abc:xyz",
                "content": '{"key": "bubbleId:abc:xyz", "value": "{"y": 2}"}',
            },
        ],
        _USER,
    )
    assert result.ingested == 2


def test_send_agent_activity_batch_treats_detail_as_failure() -> None:
    """An API error (Detail) is reported as a failed batch, not an ingest."""
    client = MagicMock()
    client.send_agent_activity.return_value = Detail("boom", status_code=500)
    result = send_agent_activity_batch(client, [_event("a", 1)], _USER)
    assert result.success is False
    assert result.ingested == 0
    assert result.dropped == 0


def test_collect_agent_activity_counts_detail_response_as_failed_batch() -> None:
    client = MagicMock()
    client.send_agent_activity.return_value = Detail("boom", status_code=500)
    report = collect_agent_activity(client, _USER, [_make_agent("a", [_event("a", 1)])])
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
        record_offset=str(i).zfill(7),
        content=f'{{"i": {i}}}',
    )


def test_collect_agent_activity_attaches_user_to_each_batch() -> None:
    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(
        success=True, ingested=1, dropped=0
    )
    collect_agent_activity(client, _USER, [_make_agent("a", [_event("a", 1)])])

    args, _ = client.send_agent_activity.call_args
    assert args[1] == _USER


def test_collect_agent_activity_batches_in_chunks_of_batch_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An agent yielding more than BATCH_SIZE events triggers multiple sends."""
    monkeypatch.setattr(orchestrator, "BATCH_SIZE", 5)
    events = [_event("a", i) for i in range(orchestrator.BATCH_SIZE + 3)]
    agent = _make_agent("a", events)
    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(
        success=True, ingested=orchestrator.BATCH_SIZE, dropped=0
    )

    report = collect_agent_activity(client, _USER, [agent])

    assert client.send_agent_activity.call_count == 2
    assert report.parsed == orchestrator.BATCH_SIZE + 3


def test_collect_agent_activity_aggregates_per_agent_counts() -> None:
    events_a = [_event("a", 1)]
    events_b = [_event("b", 2)]
    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(
        success=True, ingested=2, dropped=0
    )

    report = collect_agent_activity(
        client, _USER, [_make_agent("a", events_a), _make_agent("b", events_b)]
    )

    assert report.parsed == 2
    assert report.ingested == 2


def test_collect_agent_activity_handles_empty_agents() -> None:
    client = MagicMock()
    report = collect_agent_activity(client, _USER, [_make_agent("a", [])])
    client.send_agent_activity.assert_not_called()
    assert report.parsed == 0


def test_collect_agent_activity_flushes_on_byte_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Large records flush on the byte budget before reaching BATCH_SIZE count."""
    monkeypatch.setattr(orchestrator, "MAX_BATCH_BYTES", 1024)
    big = "x" * (
        orchestrator.MAX_BATCH_BYTES + 1
    )  # each event alone exceeds the budget
    events = [
        AgentActivityEvent(
            agent_name="a",
            source_kind="k",
            source_path="f",
            record_offset=str(i).zfill(7),
            content=big,
        )
        for i in range(3)
    ]
    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(ingested=1, dropped=0)

    report = collect_agent_activity(client, _USER, [_make_agent("a", events)])

    # 3 oversized events => 3 separate sends, none waiting for the count threshold.
    assert client.send_agent_activity.call_count == 3
    assert report.parsed == 3


def test_collect_agent_activity_counts_network_error_as_failed_batch() -> None:
    """A network error while sending a batch is counted as a failed batch."""
    client = MagicMock()
    client.send_agent_activity.side_effect = requests.exceptions.ConnectionError("down")
    report = collect_agent_activity(client, _USER, [_make_agent("a", [_event("a", 1)])])

    assert report.parsed == 1
    assert report.ingested == 0
    assert report.failed_batches == 1


def test_collect_agent_activity_aggregates_dropped_from_response() -> None:
    """The server's dropped count (records it could not scan) is surfaced."""
    client = MagicMock()
    client.send_agent_activity.return_value = MagicMock(
        success=True, ingested=0, dropped=3
    )
    report = collect_agent_activity(client, _USER, [_make_agent("a", [_event("a", 1)])])

    assert report.dropped == 3
