import os
from typing import List

import click

from ggshield.core.cache import ReadOnlyCache
from ggshield.core.extra_headers import add_extra_header
from ggshield.core.git_shell import check_git_dir, get_list_commit_SHA
from ggshield.core.utils import (
    EMPTY_SHA,
    ScanContext,
    ScanMode,
    SupportedCI,
    handle_exception,
)
from ggshield.scan.repo import scan_commit_range


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
            f"TRAVIS_COMMIT_RANGE: {commit_range}" f"\nTRAVIS_COMMIT: {commit_sha}",
            err=True,
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
        click.echo(f"BITBUCKET_COMMIT: {commit_sha}", err=True)

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
        click.echo(
            f"CIRCLE_RANGE: {compare_range}\nCIRCLE_SHA1: {commit_sha}", err=True
        )

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
    merge_request_target_branch = os.getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")

    if verbose:
        click.echo(
            f"CI_MERGE_REQUEST_TARGET_BRANCH_NAME: {merge_request_target_branch}\n"
            f"CI_COMMIT_BEFORE_SHA: {before_sha}\n"
            f"CI_COMMIT_SHA: {commit_sha}",
            err=True,
        )

    if before_sha and before_sha != EMPTY_SHA:
        commit_list = get_list_commit_SHA("{}~1...".format(before_sha))
        if commit_list:
            return commit_list

    if merge_request_target_branch and merge_request_target_branch != EMPTY_SHA:
        commit_list = get_list_commit_SHA(
            "origin/{}...".format(merge_request_target_branch)
        )
        if commit_list:
            return commit_list

    commit_list = get_list_commit_SHA("{}~1...".format(commit_sha))
    if commit_list:
        return commit_list

    raise click.ClickException(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"  CI_MERGE_REQUEST_TARGET_BRANCH_NAME: {merge_request_target_branch}\n"
        f"  CI_COMMIT_BEFORE_SHA: {before_sha}\n"
        f"  CI_COMMIT_SHA: {commit_sha}"
    )


def github_actions_range(verbose: bool) -> List[str]:  # pragma: no cover
    push_before_sha = os.getenv("GITHUB_PUSH_BEFORE_SHA")
    push_base_sha = os.getenv("GITHUB_PUSH_BASE_SHA")
    pull_req_base_sha = os.getenv("GITHUB_PULL_BASE_SHA")
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

    if push_before_sha and push_before_sha != EMPTY_SHA:
        commit_list = get_list_commit_SHA("{}...".format(push_before_sha))
        if commit_list:
            return commit_list

    if pull_req_base_sha and pull_req_base_sha != EMPTY_SHA:
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
        commit_list = get_list_commit_SHA("{}~1...".format(head_sha))
        if commit_list:
            return commit_list

    raise click.ClickException(
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
        commit_list = get_list_commit_SHA("{}..".format(before_sha))
        if commit_list:
            return commit_list

    raise click.ClickException(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"  DRONE_COMMIT_BEFORE: {before_sha}"
    )


def azure_range(verbose: bool) -> List[str]:  # pragma: no cover
    head_commit = os.getenv("BUILD_SOURCEVERSION")

    if verbose:
        click.echo(f"BUILD_SOURCEVERSION: {head_commit}\n", err=True)

    if head_commit:
        commit_list = get_list_commit_SHA("{}~1...".format(head_commit))
        if commit_list:
            return commit_list

    raise click.ClickException(
        "Unable to get commit range. Please submit an issue with the following info:\n"
        "  Repository URL: <Fill if public>\n"
        f"  BUILD_SOURCEVERSION: {head_commit}"
    )


@click.command()
@click.pass_context
def ci_cmd(ctx: click.Context) -> int:
    """
    scan in a CI environment.
    """
    config = ctx.obj["config"]
    try:
        check_git_dir()
        if not (
            os.getenv("CI") or os.getenv("JENKINS_HOME") or os.getenv("BUILD_BUILDID")
        ):
            raise click.ClickException(
                "`secret scan ci` should only be used in a CI environment."
            )

        if os.getenv("GITLAB_CI"):
            commit_list = gitlab_ci_range(config.verbose)
            ci_mode = SupportedCI.GITLAB
        elif os.getenv("GITHUB_ACTIONS"):
            commit_list = github_actions_range(config.verbose)
            ci_mode = SupportedCI.GITHUB
        elif os.getenv("TRAVIS"):
            commit_list = travis_range(config.verbose)
            ci_mode = SupportedCI.TRAVIS
        elif os.getenv("JENKINS_HOME") or os.getenv("JENKINS_URL"):
            commit_list = jenkins_range(config.verbose)
            ci_mode = SupportedCI.JENKINS
        elif os.getenv("CIRCLECI"):
            commit_list = circle_ci_range(config.verbose)
            ci_mode = SupportedCI.CIRCLECI
        elif os.getenv("BITBUCKET_COMMIT"):
            commit_list = bitbucket_pipelines_range(config.verbose)
            ci_mode = SupportedCI.BITBUCKET
        elif os.getenv("DRONE"):
            commit_list = drone_range(config.verbose)
            ci_mode = SupportedCI.DRONE
        elif os.getenv("BUILD_BUILDID"):
            commit_list = azure_range(config.verbose)
            ci_mode = SupportedCI.AZURE
        else:
            raise click.ClickException(
                f"Current CI is not detected or supported."
                f" Supported CIs: {', '.join([ci.value for ci in SupportedCI])}."
            )

        add_extra_header(ctx, "Ci-Mode", ci_mode.name)

        mode_header = f"{ScanMode.CI.value}/{ci_mode.value}"

        if config.verbose:
            click.echo(f"Commits to scan: {len(commit_list)}", err=True)

        scan_context = ScanContext(
            scan_mode=mode_header,
            command_path=ctx.command_path,
        )

        return scan_commit_range(
            client=ctx.obj["client"],
            cache=ReadOnlyCache(),
            commit_list=commit_list,
            output_handler=ctx.obj["output_handler"],
            exclusion_regexes=ctx.obj["exclusion_regexes"],
            matches_ignore=config.secret.ignored_matches,
            scan_context=scan_context,
            ignored_detectors=config.secret.ignored_detectors,
        )
    except Exception as error:
        return handle_exception(error, config.verbose)
