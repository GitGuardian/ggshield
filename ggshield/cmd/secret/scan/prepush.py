import logging
import os
import sys
from typing import List, Optional, Tuple

import click

from ggshield.core.git_shell import check_git_dir, get_list_commit_SHA
from ggshield.core.utils import (
    EMPTY_SHA,
    EMPTY_TREE,
    ScanContext,
    ScanMode,
    handle_exception,
)
from ggshield.scan.repo import scan_commit_range


logger = logging.getLogger(__name__)


@click.command()
@click.argument("prepush_args", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def prepush_cmd(ctx: click.Context, prepush_args: List[str]) -> int:  # pragma: no cover
    """
    scan as a pre-push git hook.
    """
    config = ctx.obj["config"]

    local_commit, remote_commit = collect_from_precommit_env()
    if local_commit is None or remote_commit is None:
        local_commit, remote_commit = collect_from_stdin()

    if local_commit == EMPTY_SHA:
        click.echo("Deletion event or nothing to scan.", err=True)
        return 0

    if remote_commit == EMPTY_SHA:
        click.echo(
            f"New tree event. Scanning last {config.max_commits_for_hook} commits.",
            err=True,
        )
        before = EMPTY_TREE
        after = local_commit
        cmd_range = (
            f"--max-count={config.max_commits_for_hook+1} {EMPTY_TREE} {local_commit}"
        )
    else:
        before = remote_commit
        after = local_commit
        cmd_range = f"--max-count={config.max_commits_for_hook+1} {remote_commit}...{local_commit}"  # noqa

    commit_list = get_list_commit_SHA(cmd_range)

    if not commit_list:
        click.echo(
            "Unable to get commit range.\n"
            f"  before: {before}\n"
            f"  after: {after}\n"
            "Skipping pre-push hook\n",
            err=True,
        )
        return 0

    if len(commit_list) > config.max_commits_for_hook:
        click.echo(
            f"Too many commits. Scanning last {config.max_commits_for_hook} commits\n",
            err=True,
        )
        commit_list = commit_list[-config.max_commits_for_hook :]

    if config.verbose:
        click.echo(f"Commits to scan: {len(commit_list)}", err=True)

    try:
        check_git_dir()

        scan_context = ScanContext(
            scan_mode=ScanMode.PRE_PUSH,
            command_path=ctx.command_path,
        )

        return scan_commit_range(
            client=ctx.obj["client"],
            cache=ctx.obj["cache"],
            commit_list=commit_list,
            output_handler=ctx.obj["output_handler"],
            exclusion_regexes=ctx.obj["exclusion_regexes"],
            matches_ignore=config.secret.ignored_matches,
            scan_context=scan_context,
            ignored_detectors=config.secret.ignored_detectors,
        )
    except Exception as error:
        return handle_exception(error, config.verbose)


def collect_from_stdin() -> Tuple[str, str]:
    """
    Collect pre-commit variables from stdin.
    """
    prepush_input = sys.stdin.read().split()
    logger.debug("input=%s", prepush_input)
    if len(prepush_input) < 4:
        # Then it's either a tag or a deletion event
        local_commit = EMPTY_SHA
        remote_commit = EMPTY_SHA
    else:
        local_commit = prepush_input[1].strip()
        remote_commit = prepush_input[3].strip()

    logger.debug("refs=(%s, %s)", local_commit, remote_commit)
    return (local_commit, remote_commit)


def collect_from_precommit_env() -> Tuple[Optional[str], Optional[str]]:
    """
    Collect from pre-commit framework environment.
    """
    # pre-commit framework <2.2.0
    local_commit = os.getenv("PRE_COMMIT_SOURCE", None)
    remote_commit = os.getenv("PRE_COMMIT_ORIGIN", None)

    if local_commit is None or remote_commit is None:
        # pre-commit framework >=2.2.0
        local_commit = os.getenv("PRE_COMMIT_FROM_REF", None)
        remote_commit = os.getenv("PRE_COMMIT_TO_REF", None)

    logger.debug("refs=(%s, %s)", local_commit, remote_commit)
    return (local_commit, remote_commit)
