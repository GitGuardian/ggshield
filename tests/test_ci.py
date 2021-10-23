from typing import Dict
from unittest.mock import Mock, patch

import pytest

from ggshield.ci import EMPTY_SHA, gitlab_ci_range


@patch("ggshield.ci.get_list_commit_SHA")
@patch("ggshield.ci.check_git_dir")
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
def test_gitab_ci_range(
    _: Mock,
    get_list_mock: Mock,
    monkeypatch,
    env: Dict[str, str],
    expected_parameter: str,
):
    monkeypatch.setenv("CI", "1")
    monkeypatch.setenv("GITLAB_CI", "1")
    for k, v in env.items():
        monkeypatch.setenv(k, v)

    get_list_mock.return_value = ["a"] * 51

    gitlab_ci_range(verbose=False)
    get_list_mock.assert_called_once_with(expected_parameter)
