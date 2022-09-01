import click

from ggshield.core.git_shell import get_list_commit_SHA
from ggshield.core.utils import ScanContext, ScanMode, handle_exception
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

        scan_context = ScanContext(
            scan_mode=ScanMode.COMMIT_RANGE,
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
