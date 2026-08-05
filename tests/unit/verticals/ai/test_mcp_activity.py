from unittest.mock import MagicMock, patch

import requests
from pygitguardian.models import Detail, MCPActivityResponse, UserInfo

from ggshield.verticals.ai.mcp import send_mcp_activity
from ggshield.verticals.ai.models import (
    AIDiscovery,
    EventType,
    HookPayload,
    MCPActivityRequest,
    Tool,
)


def _user() -> UserInfo:
    return UserInfo(
        hostname="host", username="user", machine_id="mid", user_email="u@e.com"
    )


def _ai_discovery() -> AIDiscovery:
    return AIDiscovery(user=_user(), servers=[], discovery_duration=0.1)


def _mcp_activity_request() -> MCPActivityRequest:
    return MCPActivityRequest(
        user=_user(),
        tool="my_tool",
        server="my_server",
        agent="cursor",
        model="gpt-4",
        cwd="/tmp",
        input={"key": "value"},
    )


def _payload() -> HookPayload:
    agent = MagicMock()
    return HookPayload(
        event_type=EventType.PRE_TOOL_USE,
        tool=Tool.MCP,
        content="content",
        identifier="id",
        agent=agent,
        raw={},
    )


class TestSendMCPActivity:
    @patch("ggshield.verticals.ai.mcp.refresh_and_maybe_submit_discovery")
    def test_successful_response(self, mock_refresh: MagicMock):
        mock_refresh.return_value = _ai_discovery()
        payload = _payload()
        payload.agent.parse_mcp_activity = MagicMock(
            return_value=_mcp_activity_request()
        )

        activity = MCPActivityResponse(allowed=False, reason="blocked by policy")
        client = MagicMock()
        client.log_mcp_activity.return_value = activity

        result = send_mcp_activity(client, payload)

        assert result.allowed is False
        assert result.reason == "blocked by policy"

    @patch("ggshield.verticals.ai.mcp.refresh_and_maybe_submit_discovery")
    def test_an_api_error_is_no_answer_not_an_allow(self, mock_refresh: MagicMock):
        """A Detail response means the API did not decide. Returning an allow here
        is what made an unreachable policy endpoint silently permit every call."""
        mock_refresh.return_value = _ai_discovery()
        payload = _payload()
        payload.agent.parse_mcp_activity = MagicMock(
            return_value=_mcp_activity_request()
        )

        client = MagicMock()
        client.log_mcp_activity.return_value = Detail(
            status_code=400, detail="Validation Error"
        )

        assert send_mcp_activity(client, payload) is None

    @patch("ggshield.verticals.ai.mcp.refresh_and_maybe_submit_discovery")
    def test_a_network_error_is_no_answer(self, mock_refresh: MagicMock):
        mock_refresh.return_value = _ai_discovery()
        payload = _payload()
        payload.agent.parse_mcp_activity = MagicMock(
            return_value=_mcp_activity_request()
        )

        client = MagicMock()
        client.log_mcp_activity.side_effect = requests.exceptions.ConnectionError(
            "offline"
        )

        assert send_mcp_activity(client, payload) is None

    @patch("ggshield.verticals.ai.mcp.refresh_and_maybe_submit_discovery")
    def test_an_unexpected_error_is_no_answer(self, mock_refresh: MagicMock):
        """A bug must still fail open, and must not masquerade as a policy allow."""
        mock_refresh.return_value = _ai_discovery()
        payload = _payload()
        payload.agent.parse_mcp_activity = MagicMock(
            side_effect=TypeError("bug in parse_mcp_activity")
        )

        assert send_mcp_activity(MagicMock(), payload) is None

    @patch("ggshield.verticals.ai.mcp.refresh_and_maybe_submit_discovery")
    def test_discovery_failing_is_no_answer(self, mock_refresh: MagicMock):
        """refresh_and_maybe_submit_discovery used to sit outside the try, so its
        failures escaped the MCP fail-open and surfaced as 'could not scan'."""
        mock_refresh.side_effect = OSError("cannot walk the filesystem")

        assert send_mcp_activity(MagicMock(), _payload()) is None

    def test_a_non_mcp_payload_is_a_genuine_allow(self):
        """Nothing to evaluate is not a failure: it must not warn, or every Read,
        Bash and Edit call would carry a warning."""
        payload = _payload()
        payload.tool = Tool.READ

        result = send_mcp_activity(MagicMock(), payload)

        assert result is not None
        assert result.allowed is True

    @patch("ggshield.verticals.ai.mcp.refresh_and_maybe_submit_discovery")
    def test_refresh_called_before_submission(self, mock_refresh: MagicMock):
        mock_refresh.return_value = _ai_discovery()
        payload = _payload()
        payload.agent.parse_mcp_activity = MagicMock(
            return_value=_mcp_activity_request()
        )

        response_data = MCPActivityResponse(allowed=True, reason="")
        mock_response = MagicMock()
        mock_response.ok = True
        mock_response.text = response_data.to_json()

        client = MagicMock()
        client.post.return_value = mock_response

        send_mcp_activity(client, payload)

        mock_refresh.assert_called_once_with(client)
