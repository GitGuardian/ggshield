from unittest.mock import Mock, patch

from click.testing import CliRunner

from ggshield.__main__ import cli
from tests.unit.conftest import assert_invoke_ok


@patch("ggshield.__main__._check_for_updates")
def test_no_check_for_updates_before_subcommand(
    check_for_updates_mock: Mock, cli_fs_runner: CliRunner
):
    """
    GIVEN --no-check-for-updates passed before the subcommand
    WHEN the command finishes
    THEN the update check is skipped
    """
    result = cli_fs_runner.invoke(cli, ["--no-check-for-updates", "config", "list"])
    assert_invoke_ok(result)
    check_for_updates_mock.assert_called_once_with(False)
