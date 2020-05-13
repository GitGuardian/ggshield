import os
from typing import Iterable, List, Optional

import click

from .git_shell import shell
from .message import process_scan_result
from .pygitguardian import GGClient
from .scannable import Commit


SUPPORTED_CI = "[GITLAB | TRAVIS | CIRCLE | GITHUB_ACTIONS]"

GITLAB_NO_BEFORE = "0000000000000000000000000000000000000000"


def scan_ci(client: GGClient, verbose: bool, ignored_matches: Iterable[str]) -> int:
    """ Scan commits in CI environment. """
    if not os.getenv("CI"):
        raise click.ClickException("--ci should only be used in a CI environment.")

    # GITLAB
    if os.getenv("GITLAB_CI"):
        before_sha = os.getenv("CI_COMMIT_BEFORE_SHA")
        commit_sha = os.getenv("CI_COMMIT_SHA", "")
        if verbose:
            click.echo(
                f"CI_COMMIT_BEFORE_SHA: {before_sha}\nCI_COMMIT_SHA: {commit_sha}"
            )
        if before_sha and before_sha != GITLAB_NO_BEFORE:
            commit_range = "{}...".format(before_sha)
        else:
            commit_range = "{}...".format(commit_sha)

    # TRAVIS
    elif os.getenv("TRAVIS"):
        commit_range = os.getenv("TRAVIS_COMMIT_RANGE")

    # CIRCLE
    elif os.getenv("CIRCLECI"):
        commit_range = os.getenv("CIRCLE_COMMIT_RANGE")

    # GITHUB
    elif os.getenv("GITHUB_ACTIONS"):
        commit_range = "{}...{}".format(os.getenv("GITHUB_SHA"), "HEAD")

    else:
        raise click.ClickException(
            "Current CI is not detected or supported. Must be one of {}".format(
                SUPPORTED_CI
            )
        )

    return scan_commit_range(
        client=client,
        commit_range=commit_range,
        verbose=verbose,
        all_commits=False,
        ignored_matches=ignored_matches,
    )


def scan_commit_range(
    client: GGClient,
    commit_range: str,
    verbose: bool,
    all_commits: bool,
    ignored_matches: Iterable[str],
) -> int:
    """
    Scan every commit in a range.

    :param client: Public Scanning API client
    :param commit_range: Range of commits to scan (A...B)
    :param verbose: Display successfull scan's message
    """
    return_code = 0

    for sha in get_list_commit_SHA(commit_range, all_commits):
        if "fatal" in sha:
            pass
        commit = Commit(sha)
        results = commit.scan(client, ignored_matches)

        if any(result["has_leak"] for result in results) or verbose:
            click.echo("\nCommit {} :".format(sha))

        return_code = max(
            return_code,
            process_scan_result(results, hide_secrets=True, verbose=verbose),
        )

    return return_code


def get_list_commit_SHA(commit_range: Optional[str], all_commits: bool) -> List:
    """
    Retrieve the list of commit SHA from a range.
    :param commit_range: A range of commits (ORIGIN...HEAD)
    """

    if all_commits:
        return shell("git rev-list --reverse --all")

    try:
        return shell(f"git rev-list --reverse {commit_range}")
    except Exception:
        return shell("git rev-list --reverse {}".format(commit_range.split("...")[1]))
