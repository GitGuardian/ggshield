from typing import List

import click

from ggshield.core.git_shell import check_git_dir
from ggshield.core.utils import SupportedScanMode, handle_exception
from ggshield.output import TextOutputHandler
from ggshield.scan import Commit, ScanCollection


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
    output_handler = TextOutputHandler(
        show_secrets=config.secret.show_secrets, verbose=config.verbose, output=None
    )
    try:
        check_git_dir()
        results = Commit(exclusion_regexes=ctx.obj["exclusion_regexes"]).scan(
            client=ctx.obj["client"],
            cache=ctx.obj["cache"],
            matches_ignore=config.secret.ignored_matches,
            mode_header=SupportedScanMode.PRE_COMMIT.value,
            ignored_detectors=config.secret.ignored_detectors,
        )

        return output_handler.process_scan(
            ScanCollection(id="cached", type="pre-commit", results=results)
        )
    except Exception as error:
        return handle_exception(error, config.verbose)
