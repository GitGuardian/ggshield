from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.verticals.ai.models import AIDiscovery, UserInfo


def _user():
    return UserInfo(
        hostname="host", username="user", machine_id="mid", user_email="u@e.com"
    )


def _discovery():
    return AIDiscovery(user=_user(), servers=[], discovery_duration=0.1)


# ---------------------------------------------------------------------------
# ggshield secret scan ai-hook
# ---------------------------------------------------------------------------


class TestAiHookCmd:
    @patch("ggshield.cmd.secret.scan.ai_hook.AIHookScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.SecretScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.create_client_from_config")
    def test_valid_json_stdin(
        self,
        mock_client: MagicMock,
        mock_scanner_cls: MagicMock,
        mock_hook_scanner: MagicMock,
    ):
        instance = mock_hook_scanner.return_value
        instance.scan.return_value = 0

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["secret", "scan", "ai-hook"],
            input='{"event_type": "test"}',
        )

        assert result.exit_code == 0
        instance.scan.assert_called_once()

    @patch("ggshield.cmd.secret.scan.ai_hook.AIHookScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.SecretScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.create_client_from_config")
    def test_empty_stdin_returns_error(
        self,
        mock_client: MagicMock,
        mock_scanner_cls: MagicMock,
        mock_hook_scanner: MagicMock,
    ):
        instance = mock_hook_scanner.return_value
        instance.scan.side_effect = ValueError("Empty input")

        runner = CliRunner()
        result = runner.invoke(
            cli,
            ["secret", "scan", "ai-hook"],
            input="",
        )

        assert result.exit_code == 1

    @patch("ggshield.cmd.secret.scan.ai_hook.AIHookScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.SecretScanner")
    @patch("ggshield.cmd.secret.scan.ai_hook.create_client_from_config")
    def test_large_stdin_does_not_crash(
        self,
        mock_client: MagicMock,
        mock_scanner_cls: MagicMock,
        mock_hook_scanner: MagicMock,
    ):
        instance = mock_hook_scanner.return_value
        instance.scan.return_value = 0

        runner = CliRunner()
        large_input = "x" * (1024 * 1024)  # 1 MB
        result = runner.invoke(
            cli,
            ["secret", "scan", "ai-hook"],
            input=large_input,
        )

        assert result.exit_code == 0
