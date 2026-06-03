"""Orchestrate agent-activity collection across agents and ship batches to the API."""

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable, List

import requests
from pygitguardian import GGClient
from pygitguardian.models import Detail

from ggshield.verticals.ai.agent_activity.models import AgentActivityEvent


if TYPE_CHECKING:
    from ggshield.verticals.ai.models import Agent


logger = logging.getLogger(__name__)

BATCH_SIZE = 500

# Flush a batch once it reaches BATCH_SIZE events OR this many bytes of content,
# whichever comes first, so a few large records can't produce a huge request.
MAX_BATCH_BYTES = 5 * 1024 * 1024


@dataclass
class AgentActivityBatchResult:
    ingested: int
    duplicates: int
    success: bool


@dataclass
class AgentActivityReport:
    parsed: int = 0
    ingested: int = 0
    duplicates: int = 0
    failed_batches: int = 0


def send_agent_activity_batch(
    client: GGClient, events: List[AgentActivityEvent]
) -> AgentActivityBatchResult:
    """Serialise events and submit them as one batch."""
    if not events:
        return AgentActivityBatchResult(ingested=0, duplicates=0, success=True)
    payload = [e.to_dict() for e in events]
    response = client.send_agent_activity(payload)
    if isinstance(response, Detail):
        logger.warning("agent_activity: API returned an error: %s", response.detail)
        return AgentActivityBatchResult(ingested=0, duplicates=0, success=False)
    return AgentActivityBatchResult(
        ingested=response.ingested,
        duplicates=response.duplicates,
        success=True,
    )


def collect_agent_activity(
    client: GGClient, agents: "Iterable[Agent]"
) -> AgentActivityReport:
    """Walk each agent's raw sources and ship records in BATCH_SIZE-event batches."""
    report = AgentActivityReport()
    buffer: List[AgentActivityEvent] = []
    buffer_bytes = 0

    def flush() -> None:
        nonlocal buffer_bytes
        if not buffer:
            return
        try:
            result = send_agent_activity_batch(client, list(buffer))
        except requests.exceptions.RequestException as exc:
            logger.warning(
                "agent_activity: batch of %d events failed: %s", len(buffer), exc
            )
            report.failed_batches += 1
        else:
            report.ingested += result.ingested
            report.duplicates += result.duplicates
            if not result.success:
                report.failed_batches += 1
        buffer.clear()
        buffer_bytes = 0

    for agent in agents:
        for event in agent.iter_agent_activity_events():
            buffer.append(event)
            buffer_bytes += len(event.content.encode("utf-8"))
            report.parsed += 1
            if len(buffer) >= BATCH_SIZE or buffer_bytes >= MAX_BATCH_BYTES:
                flush()
    flush()
    return report
