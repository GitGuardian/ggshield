import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, List, Set

import click
from pygitguardian import GGClient

from .filter import path_filter_set
from .git_shell import get_list_all_commits, get_list_commit_SHA, shell
from .message import leak_message, no_leak_message
from .path import get_files_from_paths
from .scannable import Commit, Result


SUPPORTED_CI = "[GITLAB | TRAVIS | CIRCLE | GITHUB ACTIONS | BITBUCKET PIPELINES]"

NO_BEFORE = "0000000000000000000000000000000000000000"


def process_results(
    results: List[Result], verbose: bool, show_secrets: bool, nb_lines: int = 3,
) -> int:
    """
    Process a scan result.

    :param results: The results from scanning API
    :param nb_lines: The number of lines to display before and after a secret in the
    patch
    :param show_secrets: Show secrets value
    :param verbose: Display message even if there is no secrets
    :return: The exit code
    """

    for result in results:
        leak_message(result, show_secrets, nb_lines)

    if results:
        return 1

    if verbose:
        no_leak_message()

    return 0


def scan_path(
    client: GGClient,
    verbose: bool,
    paths: List[str],
    paths_ignore: List[str],
    recursive: bool,
    yes: bool,
    matches_ignore: Iterable[str],
    all_policies: bool,
    show_secrets: bool,
) -> int:
    files = get_files_from_paths(
        paths=paths,
        paths_ignore=paths_ignore,
        recursive=recursive,
        yes=yes,
        verbose=verbose,
    )
    return process_results(
        results=files.scan(
            client=client,
            matches_ignore=matches_ignore,
            all_policies=all_policies,
            verbose=verbose,
        ),
        show_secrets=show_secrets,
        verbose=verbose,
    )


def scan_pre_commit(
    client: GGClient,
    filter_set: Set[str],
    matches_ignore: Iterable[str],
    verbose: bool,
    all_policies: bool,
    show_secrets: bool,
):
    return process_results(
        results=Commit(filter_set=filter_set).scan(
            client=client,
            matches_ignore=matches_ignore,
            all_policies=all_policies,
            verbose=verbose,
        ),
        verbose=verbose,
        show_secrets=show_secrets,
    )


def jenkins_range(verbose: bool) -> List[str]:  # pragma: no cover
    head_commit = os.getenv("GIT_COMMIT")
    previous_commit = os.getenv("GIT_PREVIOUS_COMMIT")

    if verbose:
        click.echo(
            f"\tGIT_COMMIT: {head_commit}" f"\nGIT_PREVIOUS_COMMIT: {previous_commit}"
        )

    if previous_commit:
        commit_list = get_list_commit_SHA(f"{previous_commit}...{head_commit}")
        if commit_list:
            return commit_list

    commit_list = get_list_commit_SHA(f"{head_commit}~1...")
    if commit_list:
        return commit_list

    raise click.ClickException(
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
            f"TRAVIS_COMMIT_RANGE: {commit_range}" f"\nTRAVIS_COMMIT: {commit_sha}"
        )

    if commit_range:
        commit_list = get_list_commit_SHA(commit_range)
        if commit_list:
            return commit_list

    commit_list = get_list_commit_SHA("{}~1...".format(commit_sha))
    if commit_list:
        return commit_list

    raise click.ClickException(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "\tRepository URL: <Fill if public>\n"
        f"\tTRAVIS_COMMIT_RANGE: {commit_range}"
        f"\tTRAVIS_COMMIT: {commit_sha}"
    )


def bitbucket_pipelines_range(verbose: bool) -> List[str]:  # pragma: no cover
    commit_sha = os.getenv("BITBUCKET_COMMIT", "HEAD")
    if verbose:
        click.echo(f"BITBUCKET_COMMIT: {commit_sha}")

    commit_list = get_list_commit_SHA("{}~1...".format(commit_sha))
    if commit_list:
        return commit_list

    raise click.ClickException(
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
        click.echo(f"CIRCLE_RANGE: {compare_range}\nCIRCLE_SHA1: {commit_sha}")

    if compare_range and not compare_range.startswith("..."):
        commit_list = get_list_commit_SHA(compare_range)
        if commit_list:
            return commit_list

    commit_list = get_list_commit_SHA("{}~1...".format(commit_sha))
    if commit_list:
        return commit_list

    raise click.ClickException(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "\tRepository URL: <Fill if public>\n"
        f"\tCIRCLE_RANGE: {compare_range}\n"
        f"\tCIRCLE_SHA1: {commit_sha}"
    )


def gitlab_ci_range(verbose: bool) -> List[str]:  # pragma: no cover
    before_sha = os.getenv("CI_COMMIT_BEFORE_SHA")
    commit_sha = os.getenv("CI_COMMIT_SHA", "HEAD")
    if verbose:
        click.echo(f"CI_COMMIT_BEFORE_SHA: {before_sha}\nCI_COMMIT_SHA: {commit_sha}")
    if before_sha and before_sha != NO_BEFORE:
        commit_list = get_list_commit_SHA("{}~1...".format(before_sha))
        if commit_list:
            return commit_list

    commit_list = get_list_commit_SHA("{}~1...".format(commit_sha))
    if commit_list:
        return commit_list

    raise click.ClickException(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"  CI_COMMIT_BEFORE_SHA: {before_sha}\n"
        f"  CI_COMMIT_SHA: {commit_sha}"
    )


def github_actions_range(verbose: bool) -> List[str]:  # pragma: no cover
    push_before_sha = os.getenv("GITHUB_PUSH_BEFORE_SHA")
    push_base_sha = os.getenv("GITHUB_PUSH_BASE_SHA")
    pull_req_base_sha = os.getenv("GITHUB_PULL_BASE_SHA")
    default_branch = os.getenv("GITHUB_DEFAULT_BRANCH")
    head_sha = os.getenv("GITHUB_SHA")

    if verbose:
        click.echo(
            f"github_push_before_sha: {push_before_sha}\n"
            f"github_push_base_sha: {push_base_sha}\n"
            f"github_pull_base_sha: {pull_req_base_sha}\n"
            f"github_default_branch: {default_branch}\n"
            f"github_head_sha: {head_sha}"
        )

    if push_before_sha and push_before_sha != NO_BEFORE:
        commit_list = get_list_commit_SHA("{}...".format(push_before_sha))
        if commit_list:
            return commit_list

    if pull_req_base_sha and pull_req_base_sha != NO_BEFORE:
        commit_list = get_list_commit_SHA("{}..".format(pull_req_base_sha))
        if commit_list:
            return commit_list

    if push_base_sha and push_base_sha != "null":
        commit_list = get_list_commit_SHA("{}...".format(push_base_sha))
        if commit_list:
            return commit_list

    if default_branch:
        commit_list = get_list_commit_SHA("{}...".format(default_branch))
        if commit_list:
            return commit_list

    if head_sha:
        commit_list = get_list_commit_SHA("{}...".format(head_sha))
        if commit_list:
            return commit_list

    raise click.ClickException(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"github_push_before_sha: {push_before_sha}\n"
        f"github_push_base_sha: {push_base_sha}\n"
        f"github_pull_base_sha: {pull_req_base_sha}"
        f"github_default_branch: {default_branch}\n"
        f"github_head_sha: {head_sha}"
    )


def scan_ci(
    client: GGClient,
    verbose: bool,
    filter_set: Set[str],
    matches_ignore: Iterable[str],
    all_policies: bool,
    show_secrets: bool,
) -> int:  # pragma: no cover
    """ Scan commits in CI environment. """
    if not (os.getenv("CI") or os.getenv("JENKINS_HOME")):
        raise click.ClickException("--ci should only be used in a CI environment.")

    if os.getenv("GITLAB_CI"):
        commit_list = gitlab_ci_range(verbose)
    elif os.getenv("GITHUB_ACTIONS"):
        commit_list = github_actions_range(verbose)
    elif os.getenv("TRAVIS"):
        commit_list = travis_range(verbose)
    elif os.getenv("JENKINS_HOME"):
        commit_list = jenkins_range(verbose)
    elif os.getenv("CIRCLECI"):
        commit_list = circle_ci_range(verbose)
    elif os.getenv("BITBUCKET_COMMIT"):
        commit_list = bitbucket_pipelines_range(verbose)

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
        all_policies=all_policies,
        show_secrets=show_secrets,
    )


def scan_repo(
    client: GGClient,
    verbose: bool,
    repo: str,
    matches_ignore: Iterable[str],
    all_policies: bool,
    show_secrets: bool,
) -> int:  # pragma: no cover
    with tempfile.TemporaryDirectory() as tmpdirname:
        shell(["git", "clone", repo, tmpdirname])
        with cd(tmpdirname):
            return scan_commit_range(
                client=client,
                commit_list=get_list_all_commits(),
                verbose=verbose,
                filter_set=path_filter_set(Path(os.getcwd()), []),
                matches_ignore=matches_ignore,
                all_policies=all_policies,
                show_secrets=show_secrets,
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
    all_policies: bool,
    show_secrets: bool,
) -> int:  # pragma: no cover
    """
    Scan every commit in a range.

    :param client: Public Scanning API client
    :param commit_range: Range of commits to scan (A...B)
    :param verbose: Display successfull scan's message
    """
    return_code = 0

    for sha in commit_list:
        commit = Commit(sha, filter_set)
        results = commit.scan(
            client=client,
            matches_ignore=matches_ignore,
            all_policies=all_policies,
            verbose=verbose,
        )

        if results or verbose:
            click.echo("\nCommit {}:".format(sha))

        return_code = max(
            return_code,
            process_results(
                results=results, verbose=verbose, show_secrets=show_secrets,
            ),
        )

    return return_code
