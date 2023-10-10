from unittest.mock import Mock, patch

import click
from pygitguardian.sca_models import ComputeSCAFilesResult, SCAScanDiffOutput

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.utils.git_shell import EMPTY_SHA, get_list_commit_SHA
from ggshield.utils.os import cd


@patch("pygitguardian.GGClient.scan_diff")
@patch(
    "ggshield.cmd.sca.scan.sca_scan_utils.sca_files_from_git_repo", return_value=set()
)
@patch("ggshield.cmd.sca.scan.ci.get_current_and_previous_state_from_ci_env")
def test_sca_scan_ci_no_commit(
    get_current_and_previous_state_from_ci_env_mock: Mock,
    sca_files_from_git_repo_mock: Mock,
    scan_diff_mock: Mock,
    cli_fs_runner: click.testing.CliRunner,
    monkeypatch,
):
    """
    GIVEN a repository with no commits
    WHEN `sca scan ci` is called without --all
    THEN no scan has been triggered and the scan is successful
    """

    monkeypatch.setenv("CI", "1")
    monkeypatch.setenv("GITHUB_ACTIONS", "1")
    get_current_and_previous_state_from_ci_env_mock.return_value = (
        "HEAD",
        None,
    )

    result = cli_fs_runner.invoke(cli, ["sca", "scan", "ci"], catch_exceptions=False)

    scan_diff_mock.assert_not_called()
    assert result.exit_code == ExitCode.SUCCESS
    assert "No file to scan." in result.stdout
    assert "No SCA vulnerability has been added." in result.stdout


@patch("pygitguardian.GGClient.scan_diff")
@patch("ggshield.cmd.sca.scan.ci.get_current_and_previous_state_from_ci_env")
def test_sca_scan_ci_same_commit(
    get_current_and_previous_state_from_ci_env_mock: Mock,
    scan_diff_mock: Mock,
    cli_fs_runner: click.testing.CliRunner,
    monkeypatch,
):
    """
    GIVEN the same commits in the two states in CI
    WHEN `sca scan ci` is called without --all
    THEN no scan has been triggered and the scan is successful
    """
    monkeypatch.setenv("CI", "1")
    monkeypatch.setenv("GITHUB_ACTIONS", "1")
    get_current_and_previous_state_from_ci_env_mock.return_value = (
        "abcdefg",
        "abcdefg",
    )

    result = cli_fs_runner.invoke(cli, ["sca", "scan", "ci"], catch_exceptions=False)

    scan_diff_mock.assert_not_called()
    assert result.exit_code == ExitCode.SUCCESS
    assert "SCA scan diff comparing identical versions, scan skipped." in result.stdout
    assert "No SCA vulnerability has been added." in result.stdout


@patch("pygitguardian.GGClient.sca_scan_directory")
@patch("ggshield.cmd.sca.scan.sca_scan_utils.get_sca_scan_all_filepaths")
def test_sca_scan_all_no_files(
    scan_filepaths_mock: Mock,
    scan_directory_mock: Mock,
    cli_fs_runner: click.testing.CliRunner,
    monkeypatch,
):
    """
    GIVEN there are no files to check
    WHEN `sca scan ci` is called with --all
    THEN no scan has been triggered, and the scan is successful
    """
    monkeypatch.setenv("CI", "1")
    scan_filepaths_mock.return_value = ([], 200)

    result = cli_fs_runner.invoke(cli, ["sca", "scan", "ci", "--all"])

    scan_directory_mock.assert_not_called()
    assert result.exit_code == ExitCode.SUCCESS
    assert "No file to scan." in result.stdout
    assert "No SCA vulnerability has been found." in result.stdout


@patch("pygitguardian.GGClient.compute_sca_files")
@patch("pygitguardian.GGClient.scan_diff")
def test_sca_scan_ci_github_push_before_empty_sha(
    scan_diff_mock: Mock,
    compute_sca_files_mock: Mock,
    cli_fs_runner: click.testing.CliRunner,
    dummy_sca_repo,
    monkeypatch,
):
    """
    GIVEN an empty commit sha in a GITHUB_PUSH_BEFORE_SHA in CI
    WHEN `sca scan ci` is called without --all
    THEN no error is raised
    THEN the last commit of the branch is scanned
    """

    # Set CI env variables
    monkeypatch.setenv("CI", "1")
    monkeypatch.setenv("GITHUB_ACTIONS", "1")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_PUSH_BEFORE_SHA", EMPTY_SHA)

    # Mocks the two client calls
    compute_sca_files_mock.return_value = ComputeSCAFilesResult(
        sca_files=["Pipfile", "Pipfile.lock"]
    )
    scan_diff_mock.return_value = SCAScanDiffOutput(
        scanned_files=[], added_vulns=[], removed_vulns=[]
    )

    # Run CI scan
    with cd(str(dummy_sca_repo.path)):
        # Set two commits on the current branch
        dummy_sca_repo.git("checkout", "branch_with_vuln")
        dummy_sca_repo.create_commit("first commit")
        dummy_sca_repo.create_commit("second commit")

        # Set GITHUB_SHA to current HEAD
        head_sha = get_list_commit_SHA("HEAD", max_count=1)[0]
        monkeypatch.setenv("GITHUB_SHA", head_sha)

        result = cli_fs_runner.invoke(
            cli, ["sca", "scan", "ci", "--verbose"], catch_exceptions=False
        )

    scan_diff_mock.assert_called_once()
    assert result.exit_code == ExitCode.SUCCESS
    assert "No SCA vulnerability has been added." in result.stdout
