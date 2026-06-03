"""Orchestrate agent-activity collection across agents and ship batches to the API."""

import logging
from dataclasses import dataclass
from functools import partial
from typing import Dict, List, Set, Tuple

import requests
from pygitguardian import GGClient
from pygitguardian.models import Detail

from ggshield.verticals.ai.agent_activity.cursors import NOTHING, CursorStore, scope_for
from ggshield.verticals.ai.agent_activity.models import AgentActivityEvent


# A resumable source, identified by (agent_name, source_kind, source_path).
SourceKey = Tuple[str, str, str]


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
    """Serialise ``events`` and submit them as one batch."""
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


def _resume_lookup(
    store: CursorStore, scope: str, agent_name: str, kind: str, source_path: str
) -> int:
    """Adapter matching ``ResumeLookup`` once bound to a store/scope/agent."""
    return store.get(scope, agent_name, kind, source_path)


def _batch_high_water(
    events: List[AgentActivityEvent], resumable_kinds: Set[Tuple[str, str]]
) -> Dict[SourceKey, int]:
    """Highest record index per resumable source present in ``events``."""
    out: Dict[SourceKey, int] = {}
    for event in events:
        if (event.agent_name, event.source_kind) not in resumable_kinds:
            continue
        try:
            index = int(event.record_offset)
        except (TypeError, ValueError):
            continue
        key: SourceKey = (event.agent_name, event.source_kind, event.source_path)
        if index > out.get(key, NOTHING):
            out[key] = index
    return out


def collect_agent_activity(client: GGClient) -> AgentActivityReport:
    """Walk every supported agent's raw sources and ship records in BATCH_SIZE-event batches.

    Records already shipped on a previous run are skipped using a local cursor
    (see :mod:`ggshield.verticals.ai.agent_activity.cursors`). A source's cursor
    only advances over the contiguous prefix that was successfully ingested: a
    failed batch freezes its sources so the next run resends from the gap rather
    than skipping past it.
    """
    # Imported lazily: agent modules register agent-activity sources that subclass
    # ``ActivitySource``, so importing ``AGENTS`` at module load would create a
    # cycle (agents -> agent_activity -> orchestrator -> agents).
    from ggshield.verticals.ai.agents import AGENTS

    store = CursorStore.load()
    scope = scope_for(client)
    resumable_kinds: Set[Tuple[str, str]] = {
        (agent.name, source.kind)
        for agent in AGENTS.values()
        for source in agent.agent_activity_sources
        if source.supports_resume
    }

    report = AgentActivityReport()
    buffer: List[AgentActivityEvent] = []
    buffer_bytes = 0
    committed: Dict[SourceKey, int] = {}
    frozen: Set[SourceKey] = set()

    def flush() -> None:
        nonlocal buffer_bytes
        if not buffer:
            return
        batch_keys = _batch_high_water(buffer, resumable_kinds)
        succeeded = False
        # Records are shipped raw: GitGuardian scans and strips secrets
        # server-side before storing them, so the client stays "dumb".
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
            if result.success:
                succeeded = True
            else:
                report.failed_batches += 1
        if succeeded:
            for key, index in batch_keys.items():
                if key not in frozen:
                    committed[key] = max(committed.get(key, NOTHING), index)
        else:
            # Never advance a source past a gap left by a failed batch.
            frozen.update(batch_keys)
        buffer.clear()
        buffer_bytes = 0

    for agent in AGENTS.values():
        resume_for = partial(_resume_lookup, store, scope, agent.name)
        for event in agent.iter_agent_activity_events(resume_for=resume_for):
            buffer.append(event)
            buffer_bytes += len(event.content.encode("utf-8"))
            report.parsed += 1
            if len(buffer) >= BATCH_SIZE or buffer_bytes >= MAX_BATCH_BYTES:
                flush()
    flush()

    if committed:
        for (agent_name, kind, source_path), index in committed.items():
            store.advance(scope, agent_name, kind, source_path, index)
        store.save()

    return report
