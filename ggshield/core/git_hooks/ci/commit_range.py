import os
from typing import List, Tuple

import click

from ggshield.core.errors import UnexpectedError
from ggshield.utils.git_shell import EMPTY_SHA, get_list_commit_SHA

from .previous_commit import (
    github_pull_request_previous_commit_sha,
    github_push_previous_commit_sha,
    gitlab_push_previous_commit_sha,
)
from .supported_ci import SupportedCI


def collect_commit_range_from_ci_env(
    verbose: bool,
) -> Tuple[List[str], SupportedCI]:
    supported_ci = SupportedCI.from_ci_env()
    try:
        fcn = COLLECT_COMMIT_RANGE_FUNCTIONS[supported_ci]
    except KeyError:
        raise UnexpectedError(f"Not implemented for {supported_ci.value}")

    return fcn(verbose), supported_ci


def jenkins_range(verbose: bool) -> List[str]:  # pragma: no cover
    head_commit = os.getenv("GIT_COMMIT")
    previous_commit = os.getenv("GIT_PREVIOUS_COMMIT")

    if verbose:
        click.echo(
            f"\tGIT_COMMIT: {head_commit}" f"\nGIT_PREVIOUS_COMMIT: {previous_commit}",
            err=True,
        )

    if previous_commit:
        commit_list = get_list_commit_SHA(f"{previous_commit}...{head_commit}")
        if commit_list:
            return commit_list

    commit_list = get_list_commit_SHA(f"{head_commit}~1...")
    if commit_list:
        return commit_list

    raise UnexpectedError(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "\tRepository URL: <Fill if public>\n"
        f"\tGIT_COMMIT: {head_commit}"
        f"\tGIT_PREVIOUS_COMMIT: {previous_commit}"
    )


def travis_range(verbose: bool) -> List[str]:  # pragma: no cover
    commit_range = os.getenv("TRAVIS_COMMIT_RANGE")
    commit_sha = os.getenv("TRAVIS_COMMIT", "HEAD")

    if verbose:
        click.echo(
            f"TRAVIS_COMMIT_RANGE: {commit_range}" f"\nTRAVIS_COMMIT: {commit_sha}",
            err=True,
        )

    if commit_range:
        commit_list = get_list_commit_SHA(commit_range)
        if commit_list:
            return commit_list

    commit_list = get_list_commit_SHA(f"{commit_sha}~1...")
    if commit_list:
        return commit_list

    raise UnexpectedError(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "\tRepository URL: <Fill if public>\n"
        f"\tTRAVIS_COMMIT_RANGE: {commit_range}"
        f"\tTRAVIS_COMMIT: {commit_sha}"
    )


def bitbucket_pipelines_range(verbose: bool) -> List[str]:  # pragma: no cover
    commit_sha = os.getenv("BITBUCKET_COMMIT", "HEAD")
    if verbose:
        click.echo(f"BITBUCKET_COMMIT: {commit_sha}", err=True)

    commit_list = get_list_commit_SHA(f"{commit_sha}~1...")
    if commit_list:
        return commit_list

    raise UnexpectedError(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"  CI_COMMIT_SHA: {commit_sha}"
    )


def circle_ci_range(verbose: bool) -> List[str]:  # pragma: no cover
    """
    # Extract commit range (or single commit)
    COMMIT_RANGE=$(echo "${CIRCLE_COMPARE_URL}" | cut -d/ -f7)

    # Fix single commit, unfortunately we don't always get a commit range from Circle CI
    if [[ $COMMIT_RANGE != *"..."* ]]; then
    COMMIT_RANGE="${COMMIT_RANGE}...${COMMIT_RANGE}"
    fi
    """
    compare_range = os.getenv("CIRCLE_RANGE")
    commit_sha = os.getenv("CIRCLE_SHA1", "HEAD")

    if verbose:
        click.echo(
            f"CIRCLE_RANGE: {compare_range}\nCIRCLE_SHA1: {commit_sha}", err=True
        )

    if compare_range and not compare_range.startswith("..."):
        commit_list = get_list_commit_SHA(compare_range)
        if commit_list:
            return commit_list

    commit_list = get_list_commit_SHA(f"{commit_sha}~1...")
    if commit_list:
        return commit_list

    raise UnexpectedError(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "\tRepository URL: <Fill if public>\n"
        f"\tCIRCLE_RANGE: {compare_range}\n"
        f"\tCIRCLE_SHA1: {commit_sha}"
    )


def gitlab_ci_range(verbose: bool) -> List[str]:  # pragma: no cover
    before_sha = gitlab_push_previous_commit_sha()
    commit_sha = os.getenv("CI_COMMIT_SHA", "HEAD")
    merge_request_target_branch = os.getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")

    if verbose:
        click.echo(
            f"CI_MERGE_REQUEST_TARGET_BRANCH_NAME: {merge_request_target_branch}\n"
            f"CI_COMMIT_BEFORE_SHA: {before_sha}\n"
            f"CI_COMMIT_SHA: {commit_sha}",
            err=True,
        )

    if before_sha and before_sha != EMPTY_SHA:
        commit_list = get_list_commit_SHA(f"{before_sha}~1...")
        if commit_list:
            return commit_list

    if merge_request_target_branch and merge_request_target_branch != EMPTY_SHA:
        commit_list = get_list_commit_SHA(f"origin/{merge_request_target_branch}...")
        if commit_list:
            return commit_list

    commit_list = get_list_commit_SHA(f"{commit_sha}~1...")
    if commit_list:
        return commit_list

    raise UnexpectedError(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"  CI_MERGE_REQUEST_TARGET_BRANCH_NAME: {merge_request_target_branch}\n"
        f"  CI_COMMIT_BEFORE_SHA: {before_sha}\n"
        f"  CI_COMMIT_SHA: {commit_sha}"
    )


def github_actions_range(verbose: bool) -> List[str]:  # pragma: no cover
    push_before_sha = github_push_previous_commit_sha()
    push_base_sha = os.getenv("GITHUB_PUSH_BASE_SHA")
    pull_req_base_sha = github_pull_request_previous_commit_sha()
    default_branch = os.getenv("GITHUB_DEFAULT_BRANCH")
    head_sha = os.getenv("GITHUB_SHA", "HEAD")

    if verbose:
        click.echo(
            f"github_push_before_sha: {push_before_sha}\n"
            f"github_push_base_sha: {push_base_sha}\n"
            f"github_pull_base_sha: {pull_req_base_sha}\n"
            f"github_default_branch: {default_branch}\n"
            f"github_head_sha: {head_sha}",
            err=True,
        )

    # The PR base sha has to be checked before the push_before_sha
    # because the first one is only populated in case of PR
    # whereas push_before_sha can be populated in PR in case of
    # push force event in a PR
    if pull_req_base_sha and pull_req_base_sha != EMPTY_SHA:
        commit_list = get_list_commit_SHA(f"{pull_req_base_sha}..")
        if commit_list:
            return commit_list

    if push_before_sha and push_before_sha != EMPTY_SHA:
        commit_list = get_list_commit_SHA(f"{push_before_sha}...")
        if commit_list:
            return commit_list

    if push_base_sha and push_base_sha != "null":
        commit_list = get_list_commit_SHA(f"{push_base_sha}...")
        if commit_list:
            return commit_list

    if default_branch:
        commit_list = get_list_commit_SHA(f"{default_branch}...")
        if commit_list:
            return commit_list

    if head_sha:
        commit_list = get_list_commit_SHA(f"{head_sha}~1...")
        if commit_list:
            return commit_list

    raise UnexpectedError(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"github_push_before_sha: {push_before_sha}\n"
        f"github_push_base_sha: {push_base_sha}\n"
        f"github_pull_base_sha: {pull_req_base_sha}\n"
        f"github_default_branch: {default_branch}\n"
        f"github_head_sha: {head_sha}"
    )


def drone_range(verbose: bool) -> List[str]:  # pragma: no cover
    before_sha = os.getenv("DRONE_COMMIT_BEFORE")

    if verbose:
        click.echo(f"DRONE_COMMIT_BEFORE: {before_sha}\n", err=True)

    if before_sha and before_sha != EMPTY_SHA:
        commit_list = get_list_commit_SHA(f"{before_sha}..")
        if commit_list:
            return commit_list

    raise UnexpectedError(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"  DRONE_COMMIT_BEFORE: {before_sha}"
    )


def azure_range(verbose: bool) -> List[str]:  # pragma: no cover
    head_commit = os.getenv("BUILD_SOURCEVERSION")

    if verbose:
        click.echo(f"BUILD_SOURCEVERSION: {head_commit}\n", err=True)

    if head_commit:
        commit_list = get_list_commit_SHA(f"{head_commit}~1...")
        if commit_list:
            return commit_list

    raise UnexpectedError(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"  BUILD_SOURCEVERSION: {head_commit}"
    )


COLLECT_COMMIT_RANGE_FUNCTIONS = {
    SupportedCI.AZURE: azure_range,
    SupportedCI.DRONE: drone_range,
    SupportedCI.GITHUB: github_actions_range,
    SupportedCI.GITLAB: gitlab_ci_range,
    SupportedCI.CIRCLECI: circle_ci_range,
    SupportedCI.BITBUCKET: bitbucket_pipelines_range,
    SupportedCI.TRAVIS: travis_range,
    SupportedCI.JENKINS: jenkins_range,
}
