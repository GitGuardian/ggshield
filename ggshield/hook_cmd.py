import os
import sys
import traceback
from typing import List, Optional, Tuple

import click

from ggshield.config import MAX_PREPUSH_COMMITS
from ggshield.dev_scan import scan_commit_range
from ggshield.output import TextHandler
from ggshield.scan import Commit, ScanCollection
from ggshield.utils import EMPTY_SHA, EMPTY_TREE, SupportedScanMode

from .git_shell import check_git_dir, get_list_commit_SHA


@click.command()
@click.argument("precommit_args", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def precommit_cmd(
    ctx: click.Context, precommit_args: List[str]
) -> int:  # pragma: no cover
    """
    scan as a pre-commit git hook.
    """
    config = ctx.obj["config"]
    output_handler = TextHandler(
        show_secrets=config.show_secrets, verbose=config.verbose, output=None
    )
    try:
        check_git_dir()
        results = Commit(filter_set=ctx.obj["filter_set"]).scan(
            client=ctx.obj["client"],
            cache=ctx.obj["cache"],
            matches_ignore=config.matches_ignore,
            all_policies=config.all_policies,
            verbose=config.verbose,
            mode_header=SupportedScanMode.PRE_COMMIT.value,
        )

        return output_handler.process_scan(
            ScanCollection(id="cached", type="pre-commit", results=results)
        )[1]
    except click.exceptions.Abort:
        return 0
    except Exception as error:
        if config.verbose:
            traceback.print_exc()
        raise click.ClickException(str(error))


def collect_from_stdin() -> Tuple[str, str]:
    """
    Collect pre-commit variables from stdin.
    """
    prepush_input = sys.stdin.read().split()
    if len(prepush_input) < 4:
        # Then it's either a tag or a deletion event
        local_commit = EMPTY_SHA
        remote_commit = EMPTY_SHA
    else:
        local_commit = prepush_input[1].strip()
        remote_commit = prepush_input[3].strip()

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

    return (local_commit, remote_commit)


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
        click.echo("Deletion event or nothing to scan.")
        return 0

    if remote_commit == EMPTY_SHA:
        click.echo("New tree event. Scanning all changes.")
        before = EMPTY_TREE
        after = local_commit
        cmd_range = f"--max-count={MAX_PREPUSH_COMMITS+1} {EMPTY_TREE} {local_commit}"
    else:
        before = remote_commit
        after = local_commit
        cmd_range = f"{remote_commit}...{local_commit}"

    commit_list = get_list_commit_SHA(cmd_range)

    if not commit_list:
        click.echo(
            "Unable to get commit range.\n"
            f"  before: {before}\n"
            f"  after: {after}\n"
            "Skipping pre-push hook\n"
        )
        return 0

    if len(commit_list) > MAX_PREPUSH_COMMITS:
        click.echo("Too many commits for scanning. Skipping pre-push hook\n")
        return 0

    if config.verbose:
        click.echo(f"Commits to scan: {len(commit_list)}")

    try:
        check_git_dir()
        return scan_commit_range(
            client=ctx.obj["client"],
            cache=ctx.obj["cache"],
            commit_list=commit_list,
            output_handler=ctx.obj["output_handler"],
            verbose=config.verbose,
            filter_set=ctx.obj["filter_set"],
            matches_ignore=config.matches_ignore,
            all_policies=config.all_policies,
            scan_id=" ".join(commit_list),
            mode_header=SupportedScanMode.PRE_PUSH.value,
        )
    except click.exceptions.Abort:
        return 0
    except click.ClickException as exc:
        raise exc
    except Exception as error:
        if config.verbose:
            traceback.print_exc()
        raise click.ClickException(str(error))
