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

        ``None`` is deliberately *not* an allow. Returning an allow here is how an
        unreachable policy endpoint silently permits every MCP tool call: the
        caller cannot tell "the API said yes" from "we never managed to ask". The
        caller still fails open -- a network blip must never block a tool call --
        but it warns, the way the secret scan already warns when it could not scan.
    """

    # Not an MCP pre-tool use: nothing to evaluate, so this is a real allow and
    # must stay silent. Warning here would fire on every Read, Bash and Edit call.
    if not is_mcp_activity_payload(payload):
        return _mcp_activity_allow()

    try:
        # Inside the try on purpose: this walks the filesystem for MCP configs and
        # talks to the API, so it fails for the same reasons the request below
        # does. Left outside, its failures skipped the MCP fail-open entirely and
        # surfaced as the generic "could not scan" warning -- the wrong message,
        # since the secret scan itself was fine.
        ai_config = refresh_and_maybe_submit_discovery(client)
        request = payload.agent.parse_mcp_activity(payload, ai_config)
        response = client.log_mcp_activity(request)
    except requests.exceptions.RequestException as exc:
        # Expected and uninteresting: offline, timeout, TLS, DNS.
        logger.debug("MCP policy check could not reach the API: %s", exc)
        return None
    except Exception as exc:
        # Not expected. A bug here used to be indistinguishable from a network
        # blip; log it louder so it is findable, but still fail open.
        logger.warning("MCP policy check failed unexpectedly: %s", exc)
        return None

    if isinstance(response, Detail):
        # The API answered, but with an error rather than a policy decision.
        logger.debug("MCP policy check returned an error: %s", response.detail)
        return None

    return response
