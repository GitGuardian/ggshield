from unittest.mock import MagicMock, patch

import pytest

from ggshield.verticals.ai.user import _get_user_email, get_user_info


# ---------------------------------------------------------------------------
# get_user_info
# ---------------------------------------------------------------------------


class TestGetUserInfo:
    @patch("ggshield.verticals.ai.user._get_hostname", return_value="myhost")
    @patch("ggshield.verticals.ai.user._get_username", return_value="myuser")
    @patch("ggshield.verticals.ai.user._get_machine_id", return_value="abc-123")
    @patch("ggshield.verticals.ai.user._get_user_email", return_value="me@test.com")
    def test_populates_all_fields(self, *_mocks: MagicMock):
        info = get_user_info()
        assert info.hostname == "myhost"
        assert info.username == "myuser"
        assert info.machine_id == "abc-123"
        assert info.user_email == "me@test.com"

    @patch("ggshield.verticals.ai.user._get_hostname", return_value="h")
    @patch("ggshield.verticals.ai.user._get_username", return_value="u")
    @patch("ggshield.verticals.ai.user._get_machine_id", return_value="generated")
    @patch("ggshield.verticals.ai.user._get_user_email", return_value=None)
    def test_reuses_provided_machine_id(self, *_mocks: MagicMock):
        info = get_user_info(machine_id="provided-id")
        assert info.machine_id == "provided-id"


# ---------------------------------------------------------------------------
# _get_user_email
# ---------------------------------------------------------------------------


class TestGetUserEmail:
    @pytest.mark.parametrize(
        "run_return, expected",
        [
            pytest.param(
                MagicMock(returncode=0, stdout="me@example.com\n"),
                "me@example.com",
                id="valid_email",
            ),
            pytest.param(
                MagicMock(returncode=1, stdout=""),
                None,
                id="git_failure",
            ),
            pytest.param(
                MagicMock(returncode=0, stdout="  \n"),
                None,
                id="empty_output",
            ),
        ],
    )
    @patch("ggshield.verticals.ai.user.subprocess.run")
    def test_get_user_email(
        self, mock_run: MagicMock, run_return: MagicMock, expected: str
    ):
        mock_run.return_value = run_return
        assert _get_user_email() == expected

    @patch(
        "ggshield.verticals.ai.user.subprocess.run",
        side_effect=OSError("git not found"),
    )
    def test_returns_none_on_oserror(self, _mock: MagicMock):
        assert _get_user_email() is None
