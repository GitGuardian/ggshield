import logging
import os
import sys
from typing import List, Optional, Tuple

import click

from ggshield.core.git_shell import (
    check_git_dir,
    get_list_commit_SHA,
    git,
    is_valid_git_commit_ref,
)
from ggshield.core.text_utils import display_warning
from ggshield.core.utils import (
    EMPTY_SHA,
    EMPTY_TREE,
    ScanContext,
    ScanMode,
    handle_exception,
)
from ggshield.scan.repo import scan_commit_range


logger = logging.getLogger(__name__)

OUTDATED_HOOK_MESSAGE = """The installed pre-push hook did not pass its command-line arguments to ggshield. This can cause the hook to fail if the name of the remote you are pushing to is not "origin".

This can happen if the hook has been created manually or by an old version of ggshield.

To fix it, either edit the hook manually or make a backup of it and reinstall it with the following command:

    ggshield install -m local -t pre-push -f
"""  # noqa: E501


@click.command()
@click.argument("prepush_args", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def prepush_cmd(ctx: click.Context, prepush_args: List[str]) -> int:
    """
    scan as a pre-push git hook.
    """
    config = ctx.obj["config"]

    local_commit, remote_commit = collect_from_precommit_env()
    if local_commit is None or remote_commit is None:
        if len(prepush_args) == 0:
            display_warning(OUTDATED_HOOK_MESSAGE)
            remote_name = "origin"
        else:
            remote_name = prepush_args[0]
        local_commit, remote_commit = collect_from_stdin(remote_name)
    logger.debug("refs=(%s, %s)", local_commit, remote_commit)

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
        cmd_range = f"{EMPTY_TREE} {local_commit}"
    else:
        before = remote_commit
        after = local_commit
        cmd_range = f"{remote_commit}...{local_commit}"

    commit_list = get_list_commit_SHA(
        cmd_range, max_count=config.max_commits_for_hook + 1
    )

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


def find_branch_start(commit: str, remote: str) -> str:
    """
    Returns the first local-only commit of the branch
    """
    # List all ancestors of `commit` which are not in `remote`
    # Based on _pre_push_ns() from pre-commit
    #
    # Note: The `--remotes` argument MUST be set using a `=`: `--remotes={remote}` works,
    # but `--remotes {remote}` fails.
    output = git(
        [
            "rev-list",
            commit,
            "--topo-order",
            "--reverse",
            "--not",
            f"--remotes={remote}",
        ]
    )
    ancestors = output.splitlines()
    return ancestors[0]


def collect_from_stdin(remote_name: str) -> Tuple[str, str]:
    """
    Collect pre-commit variables from stdin.
    """
    prepush_input = sys.stdin.read().strip()
    logger.debug("input=%s", prepush_input)
    if not prepush_input:
        # Happens when there's nothing to push
        return (EMPTY_SHA, EMPTY_SHA)

    # TODO There can be more than one line here, for example when pushing multiple
    # branches. We should support this.
    line = prepush_input.splitlines()[0]
    _, local_commit, _, remote_commit = line.split(maxsplit=3)

    if is_valid_git_commit_ref(remote_commit):
        # Pushing to an existing branch
        return (local_commit, remote_commit)

    # Pushing to a new branch
    start_commit = find_branch_start(local_commit, remote_name)
    return (local_commit, f"{start_commit}~1")


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

    return (local_commit, remote_commit)
