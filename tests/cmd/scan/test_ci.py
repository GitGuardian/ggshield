import json
from typing import Dict
from unittest.mock import Mock, patch

import click
import pytest

from ggshield.cmd.main import cli
from ggshield.cmd.secret.scan.ci import EMPTY_SHA
from tests.conftest import assert_invoke_exited_with, assert_invoke_ok


@pytest.fixture(autouse=True)
def clear_current_ci_envs(monkeypatch):
    # Make sure the tests are not affected by the fact they themselves are running inside
    # the CI
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)


@patch("ggshield.cmd.secret.scan.ci.get_list_commit_SHA")
@patch("ggshield.cmd.secret.scan.ci.check_git_dir")
@pytest.mark.parametrize(
    "env,expected_parameter",
    [
        ({"CI_COMMIT_BEFORE_SHA": "before_sha"}, "before_sha~1..."),
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
            "origin/mr_target_branch_name...",
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
@pytest.mark.parametrize("json_output", (False, True))
def test_gitlab_ci_range(
    _: Mock,
    get_list_mock: Mock,
    cli_fs_runner: click.testing.CliRunner,
    monkeypatch,
    env: Dict[str, str],
    expected_parameter: str,
    json_output: bool,
):
    monkeypatch.setenv("CI", "1")
    monkeypatch.setenv("GITLAB_CI", "1")
    for k, v in env.items():
        monkeypatch.setenv(k, v)

    get_list_mock.return_value = ["a"] * 51
    cli_fs_runner.mix_stderr = False
    json_arg = ["--json"] if json_output else []
    result = cli_fs_runner.invoke(
        cli,
        [
            "-v",
            "secret",
            "scan",
            *json_arg,
            "ci",
        ],
    )
    assert_invoke_ok(result)
    if json_output:
        json.loads(result.output)
    get_list_mock.assert_called_once_with(expected_parameter)


@patch("ggshield.cmd.secret.scan.ci.scan_commit_range")
@patch("ggshield.cmd.secret.scan.ci.get_list_commit_SHA")
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
    monkeypatch,
    env: Dict[str, str],
    expected_mode: str,
):
    # GIVEN a CI env
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    get_list_mock.return_value = ["a"] * 51
    scan_commit_range_mock.return_value = 0

    # WHEN `secret scan ci` is called
    result = cli_fs_runner.invoke(cli, ["secret", "scan", "ci"])

    # THEN scan succeeds
    assert_invoke_ok(result)

    # AND scan_commit_range() is called with the right mode
    scan_commit_range_mock.assert_called_once()
    args = scan_commit_range_mock.call_args

    # TODO: When Python 3.7 is dropped, we can use the `args.kwargs` syntax
    # assert args.kwargs["scan_mode"] == expected_mode
    assert args[1]["scan_context"].scan_mode == expected_mode


@patch("ggshield.cmd.secret.scan.ci.check_git_dir")
def test_ci_cmd_does_not_work_outside_ci(_, cli_fs_runner: click.testing.CliRunner):
    # GIVEN no CI env
    # WHEN `secret scan ci` is called
    result = cli_fs_runner.invoke(cli, ["secret", "scan", "ci"])

    # THEN it fails
    assert_invoke_exited_with(result, 1)

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
    assert_invoke_exited_with(result, 1)

    # And the error message explains why
    assert "Current CI is not detected" in result.stdout
