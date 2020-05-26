import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, List, Set, Union

import click

from .filter import path_filter_set
from .git_shell import get_list_all_commits, get_list_commit_SHA, shell
from .message import process_scan_result
from .path import get_files_from_paths
from .pygitguardian import GGClient
from .scannable import Commit


SUPPORTED_CI = "[GITLAB | TRAVIS | CIRCLE | GITHUB_ACTIONS]"

NO_BEFORE = "0000000000000000000000000000000000000000"


def scan_path(
    client: GGClient,
    verbose: bool,
    paths: Union[List, str],
    paths_ignore: List[str],
    recursive: bool,
    yes: bool,
    matches_ignore: Iterable[str],
) -> int:
    files = get_files_from_paths(
        paths=paths,
        paths_ignore=paths_ignore,
        recursive=recursive,
        yes=yes,
        verbose=verbose,
    )
    return process_scan_result(files.scan(client, matches_ignore, verbose))


def scan_pre_commit(
    client: GGClient, filter_set: Set[str], matches_ignore: Iterable[str], verbose: bool
):
    return process_scan_result(
        Commit(filter_set=filter_set).scan(client, matches_ignore, verbose)
    )


def gitlab_ci_range(verbose: bool) -> List[str]:
    before_sha = os.getenv("CI_COMMIT_BEFORE_SHA")
    commit_sha = os.getenv("CI_COMMIT_SHA", "HEAD~1")
    if verbose:
        click.echo(f"CI_COMMIT_BEFORE_SHA: {before_sha}\nCI_COMMIT_SHA: {commit_sha}")
    if before_sha and before_sha != NO_BEFORE:
        commit_list = get_list_commit_SHA("{}~1...".format(before_sha))
        if len(commit_list):
            return commit_list

    commit_list = get_list_commit_SHA("{}~1...".format(commit_sha))
    if len(commit_list):
        return commit_list

    raise click.ClickException(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"  CI_COMMIT_BEFORE_SHA: {before_sha}\n"
        f"  CI_COMMIT_SHA: {commit_sha}"
    )


def github_actions_range(verbose: bool) -> List[str]:
    push_before_sha = os.getenv("GITHUB_PUSH_BEFORE_SHA")
    push_base_sha = os.getenv("GITHUB_PUSH_BASE_SHA")
    pull_req_base_sha = os.getenv("GITHUB_PULL_BASE_SHA")
    if verbose:
        click.echo(
            f"github_push_before_sha: {push_before_sha}\n"
            f"github_push_base_sha: {push_base_sha}\n"
            f"github_pull_base_sha: {pull_req_base_sha}"
        )

    if pull_req_base_sha and pull_req_base_sha != NO_BEFORE:
        commit_list = get_list_commit_SHA("{}..".format(pull_req_base_sha))
        if len(commit_list):
            return commit_list

    if push_before_sha and push_before_sha != NO_BEFORE:
        commit_list = get_list_commit_SHA("{}...".format(push_before_sha))
        if len(commit_list):
            return commit_list

    if push_base_sha and push_base_sha != "null":
        commit_list = get_list_commit_SHA("{}...".format(push_base_sha))
        if len(commit_list):
            return commit_list

    raise click.ClickException(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"github_push_before_sha: {push_before_sha}\n"
        f"github_push_base_sha: {push_base_sha}\n"
        f"github_pull_base_sha: {pull_req_base_sha}"
    )


def scan_ci(
    client: GGClient, verbose: bool, filter_set: Set[str], matches_ignore: Iterable[str]
) -> int:
    """ Scan commits in CI environment. """
    if not os.getenv("CI"):
        raise click.ClickException("--ci should only be used in a CI environment.")

    # GITLAB
    if os.getenv("GITLAB_CI"):
        commit_list = gitlab_ci_range(verbose)

    # GITHUB
    elif os.getenv("GITHUB_ACTIONS"):
        commit_list = github_actions_range(verbose)

    # TRAVIS
    elif os.getenv("TRAVIS"):

        commit_list = get_list_commit_SHA(os.getenv("TRAVIS_COMMIT_RANGE"))
    # CIRCLE
    elif os.getenv("CIRCLECI"):
        commit_list = get_list_commit_SHA(os.getenv("CIRCLE_COMMIT_RANGE"))

    else:
        raise click.ClickException(
            "Current CI is not detected or supported. Must be one of {}".format(
                SUPPORTED_CI
            )
        )

    if verbose:
        click.echo("Commits to scan: {}".format(len(commit_list)))

    return scan_commit_range(
        client=client,
        commit_list=commit_list,
        verbose=verbose,
        filter_set=filter_set,
        matches_ignore=matches_ignore,
    )


def scan_repo(
    client: GGClient, verbose: bool, repo: str, matches_ignore: Iterable[str],
) -> int:
    with tempfile.TemporaryDirectory() as tmpdirname:
        shell(["git", "clone", repo, tmpdirname])
        with cd(tmpdirname):
            scan_commit_range(
                client=client,
                commit_list=get_list_all_commits(),
                verbose=verbose,
                filter_set=path_filter_set(Path(os.getcwd()), []),
                matches_ignore=matches_ignore,
            )


@contextmanager
def cd(newdir):
    prevdir = os.getcwd()
    os.chdir(os.path.expanduser(newdir))
    try:
        yield
    finally:
        os.chdir(prevdir)


def scan_commit_range(
    client: GGClient,
    commit_list: List[str],
    verbose: bool,
    filter_set: Set[str],
    matches_ignore: Iterable[str],
) -> int:
    """
    Scan every commit in a range.

    :param client: Public Scanning API client
    :param commit_range: Range of commits to scan (A...B)
    :param verbose: Display successfull scan's message
    """
    return_code = 0

    for sha in commit_list:
        commit = Commit(sha, filter_set)
        results = commit.scan(client, matches_ignore, verbose)

        if any(result["has_leak"] for result in results) or verbose:
            click.echo("\nCommit {}:".format(sha))

        return_code = max(
            return_code,
            process_scan_result(results, hide_secrets=True, verbose=verbose),
        )

    return return_code
