from unittest.mock import MagicMock, patch

from pygitguardian.models import SecretBlockRequest, UserInfo

from ggshield.verticals.ai.models import EventType, HookPayload, Tool
from ggshield.verticals.ai.secret_block import send_secret_block


def _user() -> UserInfo:
    return UserInfo(
        hostname="host", username="user", machine_id="mid", user_email="u@e.com"
    )


def _payload() -> HookPayload:
    agent = MagicMock()
    agent.name = "claude"
    return HookPayload(
        event_type=EventType.PRE_TOOL_USE,
        tool=Tool.OTHER,
        content="content",
        identifier="id",
        agent=agent,
        raw={"tool_name": "Write", "cwd": "/home/dev/project"},
    )


class TestSendSecretBlock:
    @patch("ggshield.verticals.ai.secret_block.get_user_info")
    def test_sends_expected_request(self, mock_user: MagicMock):
        mock_user.return_value = _user()
        client = MagicMock()
        client.log_secret_block.return_value = None

        send_secret_block(client, _payload(), ["AWS Keys", "GitHub Token"], 2)

        client.log_secret_block.assert_called_once()
        request = client.log_secret_block.call_args[0][0]
        assert isinstance(request, SecretBlockRequest)
        assert request.agent == "claude"
        assert request.tool == "Write"
        assert request.cwd == "/home/dev/project"
        assert request.secret_count == 2
        assert request.detectors == ["AWS Keys", "GitHub Token"]

    @patch("ggshield.verticals.ai.secret_block.get_user_info")
    def test_fail_open_swallows_errors(self, mock_user: MagicMock):
        mock_user.return_value = _user()
        client = MagicMock()
        client.log_secret_block.side_effect = Exception("boom")

        # Must not raise: a telemetry failure should never break the hook.
        send_secret_block(client, _payload(), ["AWS Keys"], 1)
