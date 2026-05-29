"""Orchestrate raw-history collection across agents and ship batches to the API."""

import logging
from dataclasses import dataclass
from typing import List

import requests
from pygitguardian import GGClient

from ggshield.verticals.ai.agents import AGENTS
from ggshield.verticals.ai.raw_history.models import RawHistoryEvent


logger = logging.getLogger(__name__)

BATCH_SIZE = 500


@dataclass
class RawHistoryBatchResult:
    ingested: int
    duplicates: int
    success: bool


@dataclass
class RawHistoryReport:
    parsed: int = 0
    ingested: int = 0
    duplicates: int = 0
    failed_batches: int = 0


def send_raw_agent_history_batch(
    client: object, events: List[RawHistoryEvent]
) -> RawHistoryBatchResult:
    """Serialise ``events`` and submit them as one batch."""
    if not events:
        return RawHistoryBatchResult(ingested=0, duplicates=0, success=True)
    payload = [e.to_dict() for e in events]
    response = client.send_raw_agent_history(payload)
    return RawHistoryBatchResult(
        ingested=getattr(response, "ingested", 0),
        duplicates=getattr(response, "duplicates", 0),
        success=getattr(response, "success", False),
    )


def collect_raw_history(client: GGClient) -> RawHistoryReport:
    """Walk every supported agent's raw sources and ship records in BATCH_SIZE-event batches."""
    report = RawHistoryReport()
    buffer: List[RawHistoryEvent] = []

    def flush() -> None:
        if not buffer:
            return
        try:
            result = send_raw_agent_history_batch(client, list(buffer))
        except requests.exceptions.RequestException as exc:
            logger.warning(
                "raw_history: batch of %d events failed: %s", len(buffer), exc
            )
            report.failed_batches += 1
        else:
            report.ingested += result.ingested
            report.duplicates += result.duplicates
            if not result.success:
                report.failed_batches += 1
        buffer.clear()

    for agent in AGENTS.values():
        for event in agent.iter_raw_history_events():
            buffer.append(event)
            report.parsed += 1
            if len(buffer) >= BATCH_SIZE:
                flush()
    flush()
    return report
