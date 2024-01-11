import os
import subprocess
from pathlib import Path
from typing import Optional

import click

from ggshield.core.errors import UnexpectedError
from ggshield.utils.git_shell import (
    EMPTY_SHA,
    get_last_commit_sha_of_branch,
    get_list_commit_SHA,
    get_new_branch_ci_commits,
    git,
    is_valid_git_commit_ref,
)

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
    head_sha = os.getenv("GITHUB_SHA", "HEAD")
    event_name = os.getenv("GITHUB_EVENT_NAME")

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

    if push_before_sha and push_before_sha != EMPTY_SHA:
        return get_commit_except_forced_push(push_before_sha, verbose)

    if head_sha and event_name == "push":
        # New branch pushed, try to get sha from git state
        ref_type = os.getenv("GITHUB_REF_TYPE")
        ref_name = os.getenv("GITHUB_REF_NAME")
        if ref_type == "branch" and ref_name:
            return get_new_branch_parent_commit(ref_name, verbose)

        if verbose:
            click.echo("Could not find previous commit for current branch.")
            click.echo("Current branch may have been just pushed.")
            click.echo("Only scan last commit.")
        last_commits = get_list_commit_SHA(f"{head_sha}~1", max_count=1)
        if len(last_commits) == 1:
            return last_commits[0]

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
    merge_req_base_sha = gitlab_merge_request_previous_commit_sha(verbose)
    is_merge_req = bool(os.getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"))

    if verbose:
        click.echo(
            f"gitlab_push_before_sha: {push_before_sha}\n"
            f"gitlab_merge_base_sha: {merge_req_base_sha}\n",
            err=True,
        )

    # push_before_sha is always EMPTY_SHA in MR pipeline according with
    # https://docs.gitlab.com/ee/ci/variables/predefined_variables.html
    if (push_before_sha == EMPTY_SHA or is_merge_req) and merge_req_base_sha:
        # Targeted branch is empty
        if merge_req_base_sha == EMPTY_SHA:
            return None
        return merge_req_base_sha

    if push_before_sha and push_before_sha != EMPTY_SHA:
        return get_commit_except_forced_push(push_before_sha, verbose)

    # push_before_sha is also always EMPTY_SHA for the first commit of a new branch
    current_branch = os.getenv("CI_COMMIT_BRANCH")
    if current_branch:
        return get_new_branch_parent_commit(current_branch, verbose)

    raise UnexpectedError(
        "Unable to get previous commit. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"gitlab_push_before_sha: {push_before_sha}\n"
        f"gitlab_pull_base_sha: {merge_req_base_sha}\n"
    )


def gitlab_push_previous_commit_sha() -> Optional[str]:
    return os.getenv("CI_COMMIT_BEFORE_SHA")


def gitlab_merge_request_previous_commit_sha(verbose: bool) -> Optional[str]:
    targeted_branch = os.getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")

    # Not in a pull request workflow
    if targeted_branch is None:
        return None

    # Requires to fetch targeted branch to access current HEAD
    git(["fetch", "origin", targeted_branch])

    try:
        last_commit = get_last_commit_sha_of_branch(f"origin/{targeted_branch}")
    except Exception:
        # If fail to get last commit of target branch, fallback on CI env variable
        # "CI_MERGE_REQUEST_DIFF_BASE_SHA"
        # This is not the current state of the target branch but the initial state
        # of current branch
        if verbose:
            click.echo(f"Failed to get {targeted_branch} HEAD.")
            click.echo(
                f"Fallback on commit {os.getenv('CI_MERGE_REQUEST_DIFF_BASE_SHA')}"
            )
        return os.getenv("CI_MERGE_REQUEST_DIFF_BASE_SHA")

    return last_commit


def jenkins_previous_commit_sha(verbose: bool) -> Optional[str]:
    previous_commit = os.getenv("GIT_PREVIOUS_COMMIT")
    target_branch = os.getenv("CHANGE_TARGET")
    current_commit = os.getenv("GIT_COMMIT")
    current_branch = os.getenv("GIT_BRANCH")

    if verbose:
        click.echo(
            f"GIT_PREVIOUS_COMMIT: {previous_commit}\n"
            f"CHANGE_TARGET: {target_branch}\n",
            err=True,
        )

    if target_branch:
        return get_last_commit_sha_of_branch(f"origin/{target_branch}")

    if previous_commit and previous_commit != EMPTY_SHA:
        return get_commit_except_forced_push(previous_commit, verbose)

    if current_branch:
        try:
            return get_new_branch_parent_commit(current_branch, verbose)
        except subprocess.CalledProcessError:
            click.echo("Failed to retrieve initial commit from git history.")

    if current_commit:
        if verbose:
            click.echo("Could not find previous commit for current branch.")
            click.echo("Current branch may have been just pushed.")
            click.echo("Only scan last commit.")
        last_commits = get_list_commit_SHA(f"{current_commit}~1", max_count=1)
        if len(last_commits) == 1:
            return last_commits[0]

    raise UnexpectedError(
        "Unable to get previous commit. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"GIT_PREVIOUS_COMMIT: {previous_commit}\n"
        f"CHANGE_TARGET: {target_branch}\n"
    )


def azure_previous_commit_sha(verbose: bool) -> Optional[str]:
    push_before_sha = azure_push_previous_commit_sha()
    pull_req_base_sha = azure_pull_request_previous_commit_sha(verbose)

    if verbose:
        click.echo(
            f"PUSH_PREVIOUS_COMMIT: {push_before_sha}\n"
            f"PR_TARGET_COMMIT: {pull_req_base_sha}\n",
            err=True,
        )

    if pull_req_base_sha is not None:
        return pull_req_base_sha

    if push_before_sha is not None and push_before_sha != EMPTY_SHA:
        if verbose:
            click.echo(
                "The number of commits of a push event is not available in Azure pipelines."
            )
            click.echo("Scanning only last commit.")
        return get_commit_except_forced_push(push_before_sha, verbose)

    # New branch push
    current_branch = os.getenv("BUILD_SOURCEBRANCHNAME")
    if current_branch:
        return get_new_branch_parent_commit(current_branch, verbose)

    # Can't find previous SHA, return last commit
    head_commit = os.getenv("BUILD_SOURCEVERSION")
    last_commits = get_list_commit_SHA(f"{head_commit}~1", max_count=1)

    if len(last_commits) == 0:
        if verbose:
            click.echo("Unable to find commit HEAD~1.")
        return None

    if verbose:
        click.echo(
            "The number of commits of a push event is not available in Azure pipelines."
        )
        click.echo("Scanning only last commit.")

    if last_commits[0] is not None:
        return last_commits[0]

    raise UnexpectedError(
        "Unable to get previous commit. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"azure_push_before_sha: {push_before_sha}\n"
        f"azure_pull_req_base_sha: {pull_req_base_sha}\n"
    )


def azure_push_previous_commit_sha() -> Optional[str]:
    push_before_sha = os.getenv("BUILD_SOURCEVERSION")

    if not push_before_sha:
        return None

    return push_before_sha


def azure_pull_request_previous_commit_sha(verbose: bool) -> Optional[str]:
    """
    Returns commit to compare with in a PR environment in Azure.
    If env variable SYSTEM_PULLREQUEST_TARGETBRANCHNAME is not defined, not in a PR.
    Else, fetch target branch and get commit sha of its HEAD.
    If fail to get this commit sha, returns previous commit in current branch HEAD~1.
    """
    targeted_branch = os.getenv("SYSTEM_PULLREQUEST_TARGETBRANCHNAME")

    # Not in a PR CI job
    if targeted_branch is None:
        return None

    # Requires to fetch targeted branch to access current HEAD
    git(["fetch", "origin", targeted_branch])

    last_commit = get_last_commit_sha_of_branch(f"origin/{targeted_branch}")
    if last_commit is not None:
        return last_commit

    if verbose:
        click.echo("Unable to find HEAD commit sha of target branch.")
        click.echo("Scans only last commit of current branch.")

    last_commit = get_last_commit_sha_of_branch("HEAD~1")
    if last_commit is not None:
        return last_commit

    if verbose:
        click.echo("Unable to find commit HEAD~1.")
    return None


def get_new_branch_parent_commit(branch_name: str, verbose: bool) -> Optional[str]:
    """
    Assuming `branch_name` is a branch newly pushed, this returns a reference
    to the parent commit of all commits pushed on that branch.
    """
    new_commits = get_new_branch_ci_commits(branch_name, Path.cwd(), "origin")
    # New branch pushed with no commits
    if not new_commits:
        ref = f"refs/remotes/origin/{branch_name}"
        return ref if is_valid_git_commit_ref(ref) else "HEAD"
    new_branch_before_sha = f"{new_commits[-1]}^1"
    if verbose:
        click.echo(
            f"new_branch_before_sha: {new_branch_before_sha}\n",
            err=True,
        )
    if is_valid_git_commit_ref(new_branch_before_sha):
        return new_branch_before_sha
    else:
        if verbose:
            click.echo("> This might be a new repository.", err=True)
        return None


def get_commit_except_forced_push(commit: str, verbose: bool) -> Optional[str]:
    if not is_valid_git_commit_ref(commit):
        if verbose:
            click.echo("> This might be a forced push.", err=True)
        return None
    return commit


PREVIOUS_COMMIT_SHA_FUNCTIONS = {
    SupportedCI.GITLAB: gitlab_previous_commit_sha,
    SupportedCI.GITHUB: github_previous_commit_sha,
    SupportedCI.JENKINS: jenkins_previous_commit_sha,
    SupportedCI.AZURE: azure_previous_commit_sha,
}
