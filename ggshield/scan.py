import os
import tempfile
from contextlib import contextmanager
from typing import Iterable, List, Pattern, Union

import click

from .git_shell import get_list_all_commits, get_list_commit_SHA, shell
from .message import process_scan_result
from .path import get_files_from_paths
from .pygitguardian import GGClient
from .scannable import Commit


SUPPORTED_CI = "[GITLAB | TRAVIS | CIRCLE | GITHUB_ACTIONS]"

GITLAB_NO_BEFORE = "0000000000000000000000000000000000000000"


def scan_path(
    client: GGClient,
    verbose: bool,
    paths: Union[List, str],
    compiled_exclude: Pattern,
    recursive: bool,
    yes: bool,
    ignored_matches: Iterable[str],
) -> int:
    files = get_files_from_paths(paths, compiled_exclude, recursive, yes, verbose)
    return process_scan_result(files.scan(client, ignored_matches))


def scan_pre_commit(client: GGClient, ignored_matches: Iterable[str]):
    return process_scan_result(
        Commit().scan(client=client, ignored_matches=ignored_matches)
    )


def gitlab_ci_range(verbose: bool):
    before_sha = os.getenv("CI_COMMIT_BEFORE_SHA")
    commit_sha = os.getenv("CI_COMMIT_SHA", "HEAD~1")
    if verbose:
        click.echo(f"CI_COMMIT_BEFORE_SHA: {before_sha}\nCI_COMMIT_SHA: {commit_sha}")
    if before_sha and before_sha != GITLAB_NO_BEFORE:
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


def scan_ci(client: GGClient, verbose: bool, ignored_matches: Iterable[str]) -> int:
    """ Scan commits in CI environment. """
    if not os.getenv("CI"):
        raise click.ClickException("--ci should only be used in a CI environment.")

    # GITLAB
    if os.getenv("GITLAB_CI"):
        commit_list = gitlab_ci_range(verbose)

    # TRAVIS
    elif os.getenv("TRAVIS"):

        commit_list = get_list_commit_SHA(os.getenv("TRAVIS_COMMIT_RANGE"))
    # CIRCLE
    elif os.getenv("CIRCLECI"):
        commit_list = get_list_commit_SHA(os.getenv("CIRCLE_COMMIT_RANGE"))

    # GITHUB
    elif os.getenv("GITHUB_ACTIONS"):
        commit_list = get_list_commit_SHA("{}...".format(os.getenv("GITHUB_SHA")))

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
        ignored_matches=ignored_matches,
    )


def scan_repo(
    client: GGClient, verbose: bool, repo: str, ignored_matches: Iterable[str]
) -> int:
    with tempfile.TemporaryDirectory() as tmpdirname:
        shell(["git", "clone", repo, tmpdirname])
        with cd(tmpdirname):
            scan_commit_range(
                client=client,
                commit_list=get_list_all_commits(),
                verbose=verbose,
                ignored_matches=ignored_matches,
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
    ignored_matches: Iterable[str],
) -> int:
    """
    Scan every commit in a range.

    :param client: Public Scanning API client
    :param commit_range: Range of commits to scan (A...B)
    :param verbose: Display successfull scan's message
    """
    return_code = 0

    for sha in commit_list:
        commit = Commit(sha)
        results = commit.scan(client, ignored_matches)

        if any(result["has_leak"] for result in results) or verbose:
            click.echo("\nCommit {}:".format(sha))

        return_code = max(
            return_code,
            process_scan_result(results, hide_secrets=True, verbose=verbose),
        )

    return return_code
