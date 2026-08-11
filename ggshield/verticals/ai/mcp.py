import logging
from typing import Optional

import requests
from pygitguardian import GGClient
from pygitguardian.models import Detail, MCPActivityResponse

from ggshield.verticals.ai.discovery import refresh_and_maybe_submit_discovery

from .models import EventType, HookPayload, Tool


logger = logging.getLogger(__name__)


def _mcp_activity_allow() -> MCPActivityResponse:
    """A genuine allow: there is no MCP policy to evaluate for this payload."""
    return MCPActivityResponse(allowed=True, reason="")


def is_mcp_activity_payload(payload: HookPayload) -> bool:
    """Tell whether `send_mcp_activity` would do any actual work for this payload."""
    return payload.event_type == EventType.PRE_TOOL_USE and payload.tool == Tool.MCP


def send_mcp_activity(
    client: GGClient, payload: HookPayload
) -> Optional[MCPActivityResponse]:
    """Build the MCP activity request and send it to the GitGuardian API.

    Args:
        client: GitGuardian API client (same instance as secret scans).
        payload: Hook payload for the MCP pre-tool event.

    Returns:
        The API's policy answer, or ``None`` when no answer could be obtained.
        ``None`` is not an allow: the caller fails open, but warns.
    """

    # Nothing to evaluate: a genuine allow, and it must stay silent, or every
    # Read, Bash and Edit call would carry a warning.
    if not is_mcp_activity_payload(payload):
        return _mcp_activity_allow()

    try:
        # Inside the try: discovery walks the filesystem and calls the API, so it
        # fails for the same reasons the request below does.
        ai_config = refresh_and_maybe_submit_discovery(client)
        request = payload.agent.parse_mcp_activity(payload, ai_config)
        response = client.log_mcp_activity(request)
    except requests.exceptions.RequestException as exc:
        # Expected: offline, timeout, TLS, DNS.
        logger.debug("MCP policy check could not reach the API: %s", exc)
        return None
    except Exception as exc:
        # Louder, so a bug does not look like a network blip.
        logger.warning("MCP policy check failed unexpectedly: %s", exc)
        return None

    if isinstance(response, Detail):
        # The API answered, but with an error rather than a policy decision.
        logger.debug("MCP policy check returned an error: %s", response.detail)
        return None

    return response
