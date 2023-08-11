import os
from typing import Optional

import click

from ggshield.core.errors import UnexpectedError
from ggshield.core.git_shell import get_last_commit_sha_of_branch
from ggshield.core.utils import EMPTY_SHA

from .supported_ci import SupportedCI


def get_previous_commit_from_ci_env(
    verbose: bool,
) -> Optional[str]:
    """
    Returns the previous HEAD sha of the targeted branch.
    Returns None if there was no commit before.
    """
    supported_ci = SupportedCI.from_ci_env()
    try:
        fcn = PREVIOUS_COMMIT_SHA_FUNCTIONS[supported_ci]
    except KeyError:
        raise UnexpectedError(f"Not implemented for {supported_ci.value}")

    return fcn(verbose)


def github_previous_commit_sha(verbose: bool) -> Optional[str]:
    push_before_sha = github_push_previous_commit_sha()
    pull_req_base_sha = github_pull_request_previous_commit_sha()

    if verbose:
        click.echo(
            f"github_push_before_sha: {push_before_sha}\n"
            f"github_pull_base_sha: {pull_req_base_sha}\n",
            err=True,
        )

    # The PR base sha has to be checked before the push_before_sha
    # because the first one is only populated in case of PR
    # whereas push_before_sha can be populated in PR in case of
    # push force event in a PR
    if pull_req_base_sha:
        return pull_req_base_sha

    if push_before_sha:
        return push_before_sha

    raise UnexpectedError(
        "Unable to get previous commit. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"github_push_before_sha: {push_before_sha}\n"
        f"github_pull_base_sha: {pull_req_base_sha}\n"
    )


def github_push_previous_commit_sha() -> Optional[str]:
    push_before_sha = os.getenv("GITHUB_PUSH_BEFORE_SHA")

    if not push_before_sha:
        return None

    return push_before_sha


def github_pull_request_previous_commit_sha() -> Optional[str]:
    targeted_branch = os.getenv("GITHUB_BASE_REF")

    # Not in a pull request workflow
    if targeted_branch is None:
        return None

    return get_last_commit_sha_of_branch(f"remotes/origin/{targeted_branch}")


def gitlab_previous_commit_sha(verbose: bool) -> Optional[str]:
    push_before_sha = gitlab_push_previous_commit_sha()
    merge_req_base_sha = gitlab_merge_request_previous_commit_sha()

    if verbose:
        click.echo(
            f"gitlab_push_before_sha: {push_before_sha}\n"
            f"gitlab_merge_base_sha: {merge_req_base_sha}\n",
            err=True,
        )

    # push_before_sha is always EMPTY_SHA in MR pipeline according with
    # https://docs.gitlab.com/ee/ci/variables/predefined_variables.html
    if push_before_sha == EMPTY_SHA and merge_req_base_sha:
        # Targeted branch is empty
        if merge_req_base_sha == EMPTY_SHA:
            return None
        return merge_req_base_sha

    if push_before_sha and push_before_sha != EMPTY_SHA:
        return push_before_sha

    raise UnexpectedError(
        "Unable to get previous commit. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"gitlab_push_before_sha: {push_before_sha}\n"
        f"gitlab_pull_base_sha: {merge_req_base_sha}\n"
    )


def gitlab_push_previous_commit_sha() -> Optional[str]:
    return os.getenv("CI_COMMIT_BEFORE_SHA")


def gitlab_merge_request_previous_commit_sha() -> Optional[str]:
    targeted_branch = os.getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")

    # Not in a pull request workflow
    if targeted_branch is None:
        return None

    return get_last_commit_sha_of_branch(f"remotes/origin/{targeted_branch}")


PREVIOUS_COMMIT_SHA_FUNCTIONS = {
    SupportedCI.GITLAB: gitlab_previous_commit_sha,
    SupportedCI.GITHUB: github_previous_commit_sha,
}
