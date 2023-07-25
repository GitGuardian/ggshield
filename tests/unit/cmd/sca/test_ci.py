from unittest.mock import Mock, patch

import click

from ggshield.cmd.main import cli
from ggshield.core.errors import ExitCode


@patch("ggshield.sca.client.SCAClient.scan_diff")
@patch("ggshield.cmd.sca.scan.ci.get_ci_commits")
def test_sca_scan_ci_no_commit(
    get_ci_commits_mock: Mock,
    scan_diff_mock: Mock,
    cli_fs_runner: click.testing.CliRunner,
):
    """
    GIVEN there are no commits
    WHEN `secret scan ci` is called without --all
    THEN no scan has been triggered and the scan is successful
    """
    get_ci_commits_mock.return_value = ([], "")

    result = cli_fs_runner.invoke(cli, ["sca", "scan", "ci"])

    scan_diff_mock.assert_not_called()
    assert result.exit_code == ExitCode.SUCCESS
    assert "SCA scan diff comparing identical versions, scan skipped." in result.stdout
    assert "No SCA vulnerability has been added." in result.stdout


@patch("ggshield.sca.client.SCAClient.sca_scan_directory")
@patch("ggshield.cmd.sca.scan.sca_scan_utils.get_sca_scan_all_filepaths")
def test_sca_scan_all_no_files(
    scan_filepaths_mock: Mock,
    scan_directory_mock: Mock,
    cli_fs_runner: click.testing.CliRunner,
):
    """
    GIVEN there are no files to check
    WHEN `secret scan ci` is called with --all
    THEN no scan has been triggered, and the scan is successful
    """
    scan_filepaths_mock.return_value = ([], 200)

    result = cli_fs_runner.invoke(cli, ["sca", "scan", "ci", "--all"])

    scan_directory_mock.assert_not_called()
    assert result.exit_code == ExitCode.SUCCESS
    assert "No file to scan." in result.stdout
    assert "No SCA vulnerability has been found." in result.stdout
