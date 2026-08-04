from pygitguardian import GGClient
from pygitguardian.models import Detail, MCPActivityResponse

from ggshield.verticals.ai.discovery import refresh_and_maybe_submit_discovery

from .models import EventType, HookPayload, Tool


def _mcp_activity_fail_open() -> MCPActivityResponse:
    return MCPActivityResponse(allowed=True, reason="")


def is_mcp_activity_payload(payload: HookPayload) -> bool:
    """Tell whether `send_mcp_activity` would do any actual work for this payload."""
    return payload.event_type == EventType.PRE_TOOL_USE and payload.tool == Tool.MCP


def send_mcp_activity(client: GGClient, payload: HookPayload) -> MCPActivityResponse:
    """Build the MCP activity request and send it to the GitGuardian API.

    Args:
        client: GitGuardian API client (same instance as secret scans).
        payload: Hook payload for the MCP pre-tool event.

    Returns:
        Policy response from the API, or allow if the request fails (fail-open).
    """

    # if the payload is not an MCP pre-tool use, early return
    if not is_mcp_activity_payload(payload):
        return _mcp_activity_fail_open()

    ai_config = refresh_and_maybe_submit_discovery(client)
    request = payload.agent.parse_mcp_activity(payload, ai_config)

    try:
        response = client.log_mcp_activity(request)
    except Exception:
        return _mcp_activity_fail_open()

    if isinstance(response, Detail):
        return _mcp_activity_fail_open()

    return response
