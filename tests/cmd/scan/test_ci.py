import json
from typing import Dict
from unittest.mock import Mock, patch

import click
import pytest

from ggshield.cmd.main import cli
from ggshield.cmd.secret.scan.ci import EMPTY_SHA


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
            "scan",
            *json_arg,
            "ci",
        ],
    )
    assert result.exit_code == 0, result.stderr
    if json_output:
        json.loads(result.output)
    get_list_mock.assert_called_once_with(expected_parameter)
