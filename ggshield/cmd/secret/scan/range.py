import click

from ggshield.core.git_shell import get_list_commit_SHA
from ggshield.core.utils import handle_exception
from ggshield.scan.repo import scan_commit_range


@click.command()
@click.argument("commit_range", nargs=1, type=click.STRING)
@click.pass_context
def range_cmd(ctx: click.Context, commit_range: str) -> int:  # pragma: no cover
    """
    scan a defined COMMIT_RANGE in git.

    git rev-list COMMIT_RANGE to list several commits to scan.
    example: ggshield secret scan commit-range HEAD~1...
    """
    config = ctx.obj["config"]
    try:
        commit_list = get_list_commit_SHA(commit_range)
        if not commit_list:
            raise click.ClickException("invalid commit range")
        if config.verbose:
            click.echo(f"Commits to scan: {len(commit_list)}", err=True)

        return scan_commit_range(
            client=ctx.obj["client"],
            cache=ctx.obj["cache"],
            commit_list=commit_list,
            output_handler=ctx.obj["output_handler"],
            verbose=config.verbose,
            exclusion_regexes=ctx.obj["exclusion_regexes"],
            matches_ignore=config.matches_ignore,
            all_policies=config.all_policies,
            scan_id=commit_range,
            banlisted_detectors=config.banlisted_detectors,
        )
    except Exception as error:
        return handle_exception(error, config.verbose)
