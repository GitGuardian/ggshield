"""Raw AI-agent history collection: read transcript files and SQLite databases
verbatim, filter per-source, and ship to the GitGuardian API."""

from ggshield.verticals.ai.raw_history.models import RawHistoryEvent
from ggshield.verticals.ai.raw_history.orchestrator import (
    BATCH_SIZE,
    RawHistoryBatchResult,
    RawHistoryReport,
    collect_raw_history,
    send_raw_agent_history_batch,
)
from ggshield.verticals.ai.raw_history.readers import iter_jsonl, iter_sqlite_rows
from ggshield.verticals.ai.raw_history.sources import (
    HistorySource,
    JSONHistorySource,
    JSONLHistorySource,
    SQLiteHistorySource,
)


__all__ = [
    "BATCH_SIZE",
    "HistorySource",
    "JSONHistorySource",
    "JSONLHistorySource",
    "RawHistoryBatchResult",
    "RawHistoryEvent",
    "RawHistoryReport",
    "SQLiteHistorySource",
    "collect_raw_history",
    "iter_jsonl",
    "iter_sqlite_rows",
    "send_raw_agent_history_batch",
]
