import traceback
from typing import List

import click

from ggshield.dev_scan import scan_commit_range
from ggshield.output import TextHandler
from ggshield.scan import Commit, ScanCollection
from ggshield.utils import EMPTY_SHA, EMPTY_TREE

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


@click.command()
@click.argument("prepush_args", nargs=-1, type=click.UNPROCESSED)
@click.pass_context
def prepush_cmd(ctx: click.Context, prepush_args: List[str]) -> int:  # pragma: no cover
    """
    scan as a pre-push git hook.
    """
    config = ctx.obj["config"]
    local_commit = remote_commit = ""
    before = after = EMPTY_SHA
    if len(prepush_args) < 4:
        local_commit = EMPTY_SHA
    else:
        _, local_commit, _, remote_commit = (
            prepush_args[0],
            prepush_args[1],
            prepush_args[2],
            prepush_args[3],
        )

    if local_commit == EMPTY_SHA:
        click.echo("Deletion event or nothing to scan.")
        return 0

    if remote_commit == EMPTY_SHA:
        click.echo("New tree event. Scanning all changes.")
        before = EMPTY_TREE
        after = local_commit
    else:
        before = remote_commit
        after = local_commit

    commit_list = get_list_commit_SHA(f"{before}...{after}")
    if not commit_list:
        raise click.ClickException(
            "Unable to get commit range."
            " Please submit an issue with the following info:\n"
            "  Repository URL: <Fill if public>\n"
            f"  before: {before}\n"
            f"  after: {after}\n"
            f"  local_commit: {local_commit}\n"
            f"  remote_commit: {remote_commit}\n"
        )

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
        )
    except click.exceptions.Abort:
        return 0
    except click.ClickException as exc:
        raise exc
    except Exception as error:
        if config.verbose:
            traceback.print_exc()
        raise click.ClickException(str(error))
