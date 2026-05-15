"""Backfill of historical MCP activities, parsed from each agent's local state."""

import logging
from dataclasses import dataclass
from typing import List, Optional

from pygitguardian import GGClient
from pygitguardian.models import AIDiscovery, Detail, MCPActivityRequest

from .agents import AGENTS


logger = logging.getLogger(__name__)

BATCH_SIZE = 500


@dataclass
class BackfillReport:
    parsed: int = 0
    ingested: int = 0
    duplicates: int = 0
    skipped: int = 0
    error: Optional[str] = None


def backfill_mcp_history(client: GGClient, ai_config: AIDiscovery) -> BackfillReport:
    """Stream each agent's historical MCP events and ship them to the GitGuardian API."""
    report = BackfillReport()
    activities: List[MCPActivityRequest] = []

    def send_activities_batch() -> bool:
        if not activities:
            return True
        try:
            response = client.log_mcp_activities_bulk(list(activities))
        except Exception as exc:
            logger.warning("Bulk MCP activity upload failed: %s", exc)
            report.error = str(exc)
            return False
        if isinstance(response, Detail):
            logger.warning("Bulk MCP activity upload returned an error: %s", response)
            report.error = response.detail
            return False
        report.ingested += response.ingested
        report.duplicates += response.duplicates
        report.skipped += response.skipped
        activities.clear()
        return True

    for agent in AGENTS.values():
        for event in agent.iter_history_events(ai_config):
            activities.append(event)
            report.parsed += 1
            if len(activities) >= BATCH_SIZE:
                success = send_activities_batch()
                if not success:
                    return report

    send_activities_batch()
    return report
