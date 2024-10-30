import io
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, List, Optional
from unittest.mock import Mock, patch

import click
import pytest

from ggshield.__main__ import cli
from ggshield.core import ui
from ggshield.core.errors import ExitCode
from ggshield.core.git_hooks.ci.commit_range import collect_commit_range_from_ci_env
from ggshield.utils.git_shell import EMPTY_SHA
from ggshield.utils.os import cd
from tests.repository import Repository
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok


@pytest.fixture(autouse=True)
def clear_current_ci_envs(monkeypatch):
    # Make sure the tests are not affected by the fact they themselves are running inside
    # the CI
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)


@patch("ggshield.core.git_hooks.ci.commit_range.get_list_commit_SHA")
@patch(
    "ggshield.core.git_hooks.ci.commit_range.get_remote_prefix", return_value="origin/"
)
@patch("ggshield.cmd.secret.scan.ci.check_git_dir")
@pytest.mark.parametrize(
    "env,expected_parameter",
    [
        ({"CI_COMMIT_BEFORE_SHA": "before_sha"}, "before_sha~1..HEAD"),
        (
            {
                "CI_COMMIT_BEFORE_SHA": EMPTY_SHA,
                "CI_COMMIT_SHA": "commit_sha",
            },
            "commit_sha~1...",
        ),
        (
            {
                "CI_COMMIT_BEFORE_SHA": EMPTY_SHA,
                "HEAD": "HEAD",
            },
            "HEAD~1...",
        ),
        (
            {
                "CI_COMMIT_BEFORE_SHA": EMPTY_SHA,
                "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "mr_target_branch_name",
            },
            "origin/mr_target_branch_name..HEAD",
        ),
        (
            {
                "CI_COMMIT_BEFORE_SHA": EMPTY_SHA,
                "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": EMPTY_SHA,
                "CI_COMMIT_SHA": "commit_sha",
            },
            "commit_sha~1...",
        ),
        ({"CI_COMMIT_SHA": "commit_sha"}, "commit_sha~1..."),
        ({"HEAD": "head_sha"}, "HEAD~1..."),
    ],
)
def test_gitlab_ci_range(
    _: Mock,
    get_remote_prefix_mock: Mock,
    get_list_mock: Mock,
    cli_fs_runner: click.testing.CliRunner,
    monkeypatch,
    env: Dict[str, str],
    expected_parameter: str,
    capsys,
):
    """
    GIVEN a GitLab CI environment
    AND verbose mode has been activated
    WHEN gitlab_ci_range() is called
    THEN the correct commit range is requested
    AND stdout is empty (to avoid polluting redirections)
    AND stderr is not empty
    """
    ui.set_level(ui.Level.VERBOSE)

    monkeypatch.setenv("CI", "1")
    monkeypatch.setenv("GITLAB_CI", "1")
    for k, v in env.items():
        monkeypatch.setenv(k, v)

    get_list_mock.return_value = ["a"] * 51

    collect_commit_range_from_ci_env()
    get_list_mock.assert_called_once_with(expected_parameter)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err != ""


@patch("ggshield.cmd.secret.scan.ci.scan_commit_range")
@patch("ggshield.core.git_hooks.ci.commit_range.get_list_commit_SHA")
@patch("ggshield.cmd.secret.scan.ci.check_git_dir")
@pytest.mark.parametrize(
    ("env", "expected_mode"),
    [
        ({"CI": "true", "GITLAB_CI": "true"}, "ci/GITLAB"),
        ({"CI": "true", "GITHUB_ACTIONS": "true"}, "ci/GITHUB ACTIONS"),
        ({"CI": "true", "TRAVIS": "true"}, "ci/TRAVIS"),
        ({"JENKINS_HOME": "/var/jenkins"}, "ci/JENKINS HOME"),
        (
            {"CI": "true", "JENKINS_URL": "https://ci.example.com"},
            "ci/JENKINS HOME",
        ),  # Can we really have JENKINS_URL but not JENKINS_HOME?
        ({"CI": "true", "CIRCLECI": "true"}, "ci/CIRCLECI"),
        ({"CI": "true", "BITBUCKET_COMMIT": "12345abcd"}, "ci/BITBUCKET PIPELINES"),
        ({"CI": "true", "DRONE": "1", "DRONE_COMMIT_BEFORE": "c0ff331a"}, "ci/DRONE"),
        (
            {"BUILD_BUILDID": "1234", "BUILD_SOURCEVERSION": "b4dd3caf"},
            "ci/AZURE PIPELINES",
        ),
    ],
)
def test_ci_cmd_uses_right_mode_header(
    _: Mock,
    get_list_mock: Mock,
    scan_commit_range_mock: Mock,
    cli_fs_runner: click.testing.CliRunner,
    env: Dict[str, str],
    expected_mode: str,
):
    get_list_mock.return_value = ["a"] * 51
    scan_commit_range_mock.return_value = 0

    # WHEN `secret scan ci` is called
    with patch("os.getenv", env.get):
        result = cli_fs_runner.invoke(cli, ["secret", "scan", "ci"])

    # THEN scan succeeds
    assert_invoke_ok(result)

    # AND scan_commit_range() is called with the right mode
    scan_commit_range_mock.assert_called_once()
    args = scan_commit_range_mock.call_args

    assert args.kwargs["scan_context"].scan_mode == expected_mode


@patch("ggshield.cmd.secret.scan.ci.check_git_dir")
def test_ci_cmd_does_not_work_outside_ci(_, cli_fs_runner: click.testing.CliRunner):
    # GIVEN no CI env
    # WHEN `secret scan ci` is called
    result = cli_fs_runner.invoke(cli, ["secret", "scan", "ci"])

    # THEN it fails
    assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)

    # And the error message explains why
    assert "only be used in a CI environment" in result.stdout


@patch("ggshield.cmd.secret.scan.ci.check_git_dir")
def test_ci_cmd_does_not_work_if_ci_env_is_odd(
    _, monkeypatch, cli_fs_runner: click.testing.CliRunner
):
    # GIVEN an incomplete CI env
    monkeypatch.setenv("CI", "true")

    # WHEN `secret scan ci` is called
    result = cli_fs_runner.invoke(cli, ["secret", "scan", "ci"])

    # THEN it fails
    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)

    # And the error message explains why
    assert "Current CI is not detected" in result.stdout


DUMMY_REPO: Optional[tarfile.TarFile] = None


@pytest.fixture
def dummy_repo(tmp_path):
    global DUMMY_REPO
    if not DUMMY_REPO:
        DUMMY_REPO = make_dummy_repo()
    """Return a fresh copy of a dummy repo"""
    DUMMY_REPO.extractall(path=tmp_path)
    return Repository(tmp_path)


def make_dummy_repo():
    """Function to create a dummy repo as a tarfile."""
    result_buffer = io.BytesIO()
    with tempfile.TemporaryDirectory() as tmp_path_str:
        tmp_path = Path(tmp_path_str)
        repo = Repository.create(tmp_path)

        repo.create_commit("initial_commit")

        repo.create_branch("branch")
        repo.create_commit("branch_commit_1")
        repo.create_commit("branch_commit_2")

        repo.checkout("main")
        repo.create_commit("commit_main_1")
        repo.create_commit("commit_main_2")

        repo.create_branch("unrelated_branch")
        repo.create_commit("unrelated_branch_commit")

        result_tar = tarfile.TarFile(fileobj=result_buffer, mode="w")
        result_tar.add(tmp_path_str, arcname="./")
    result_buffer.seek(0)
    return tarfile.TarFile(fileobj=result_buffer, mode="r")


def subjets_for_commits(commit_shas: List[str], dummy_repo: Repository) -> List[str]:
    return [
        dummy_repo.git("show", sha, "--pretty=format:%s", "-s") for sha in commit_shas
    ]


@pytest.mark.parametrize(
    ("env_vars", "expected_subjects"),
    [
        ({"GITHUB_ACTIONS": 1}, ["branch_commit_2"]),
        ({"GITHUB_ACTIONS": 1, "GITHUB_SHA": "branch"}, ["branch_commit_2"]),
        (
            {"GITHUB_ACTIONS": 1, "GITHUB_SHA": "branch~1"},
            ["branch_commit_1", "branch_commit_2"],
        ),
        (
            {
                "GITHUB_ACTIONS": 1,
                "GITHUB_SHA": "branch",
                "GITHUB_DEFAULT_BRANCH": "main",
            },
            ["branch_commit_1", "branch_commit_2"],
        ),
        (
            {
                "GITHUB_ACTIONS": 1,
                "GITHUB_SHA": "branch",
                "GITHUB_DEFAULT_BRANCH": "main",
                "GITHUB_PUSH_BASE_SHA": "branch~1",
            },
            ["branch_commit_2"],
        ),
        (
            {
                "GITHUB_ACTIONS": 1,
                "GITHUB_SHA": "branch",
                "GITHUB_DEFAULT_BRANCH": "main",
                "GITHUB_PUSH_BASE_SHA": "branch~1",
                "GITHUB_BASE_REF": "main",
            },
            ["branch_commit_1", "branch_commit_2"],
        ),
        (
            {
                "GITHUB_ACTIONS": 1,
                "GITHUB_SHA": "branch",
                "GITHUB_DEFAULT_BRANCH": "main",
                "GITHUB_PUSH_BASE_SHA": "branch~1",
                "GITHUB_BASE_REF": EMPTY_SHA,
            },
            ["branch_commit_2"],
        ),
        (
            {
                "GITHUB_ACTIONS": 1,
                "GITHUB_SHA": "branch",
                "GITHUB_DEFAULT_BRANCH": "main",
                "GITHUB_PUSH_BASE_SHA": EMPTY_SHA,
                "GITHUB_BASE_REF": EMPTY_SHA,
            },
            ["branch_commit_1", "branch_commit_2"],
        ),
        (
            {"TRAVIS": 1, "TRAVIS_COMMIT_RANGE": "branch~2..branch"},
            ["branch_commit_1", "branch_commit_2"],
        ),
        (
            {"TRAVIS": 1, "TRAVIS_COMMIT_RANGE": "...branch"},
            ["branch_commit_2"],
        ),
        (
            {
                "GITLAB_CI": 1,
                "CI_COMMIT_SHA": "branch",
                "CI_COMMIT_BEFORE_SHA": "branch~1",
            },
            ["branch_commit_1", "branch_commit_2"],
        ),
    ],
)
def test_collect_commit_range_from_ci_env(
    env_vars,
    expected_subjects,
    monkeypatch,
    cli_fs_runner: click.testing.CliRunner,
    dummy_repo: Repository,
):
    env_vars["CI"] = "1"
    dummy_repo.checkout("branch")

    with patch("os.getenv", env_vars.get), cd(str(dummy_repo.path)):
        commits, _ = collect_commit_range_from_ci_env()

    assert subjets_for_commits(commits, dummy_repo) == expected_subjects
