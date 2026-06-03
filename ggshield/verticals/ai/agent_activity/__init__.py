"""AI-agent activity collection: read transcript files and SQLite databases and
ship each record **raw** (verbatim) to the GitGuardian API, which scans the
content and strips secrets server-side before storing it."""

from ggshield.verticals.ai.agent_activity.models import AgentActivityEvent
from ggshield.verticals.ai.agent_activity.orchestrator import (
    BATCH_SIZE,
    AgentActivityBatchResult,
    AgentActivityReport,
    collect_agent_activity,
    send_agent_activity_batch,
)
from ggshield.verticals.ai.agent_activity.readers import iter_jsonl, iter_sqlite_rows
from ggshield.verticals.ai.agent_activity.sources import (
    ActivitySource,
    JSONActivitySource,
    JSONLActivitySource,
    SQLiteActivitySource,
)


__all__ = [
    "BATCH_SIZE",
    "ActivitySource",
    "JSONActivitySource",
    "JSONLActivitySource",
    "AgentActivityBatchResult",
    "AgentActivityEvent",
    "AgentActivityReport",
    "SQLiteActivitySource",
    "collect_agent_activity",
    "iter_jsonl",
    "iter_sqlite_rows",
    "send_agent_activity_batch",
]
