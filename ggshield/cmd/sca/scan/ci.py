from pathlib import Path
from typing import Any, Optional, Sequence

import click

from ggshield.cmd.common_options import all_option, directory_argument
from ggshield.cmd.sca.scan.sca_scan_utils import (
    create_output_handler,
    display_sca_beta_warning,
    sca_scan_all,
    sca_scan_diff,
)
from ggshield.cmd.sca.scan.scan_common_options import (
    add_sca_scan_common_options,
    update_context,
)
from ggshield.cmd.utils.ci import get_ci_commits
from ggshield.core.errors import handle_exception
from ggshield.sca.collection.collection import (
    SCAScanAllVulnerabilityCollection,
    SCAScanDiffVulnerabilityCollection,
)


@click.command()
@add_sca_scan_common_options()
@click.pass_context
@directory_argument
@all_option
@display_sca_beta_warning
def scan_ci_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
    directory: Optional[Path],
    all: bool,
    **kwargs: Any,
) -> int:
    """
    scan in a CI environment.
    """
    if directory is None:
        directory = Path().resolve()

    # Adds client and required parameters to the context
    update_context(ctx, exit_zero, minimum_severity, ignore_paths)

    config = ctx.obj["config"]
    try:
        output_handler = create_output_handler(ctx)
        if all:
            result = sca_scan_all(ctx, directory)
            scan = SCAScanAllVulnerabilityCollection(id=str(directory), result=result)
            return output_handler.process_scan_all_result(scan)

        commit_count = len(get_ci_commits(config)[0])

        if config.verbose:
            click.echo(f"Commits to scan: {commit_count}", err=True)
        result = sca_scan_diff(
            ctx=ctx,
            directory=directory,
            ref=f"HEAD~{commit_count}" if commit_count > 0 else "HEAD",
            include_staged=False,
        )
        scan = SCAScanDiffVulnerabilityCollection(id=str(directory), result=result)
        return output_handler.process_scan_diff_result(scan)

    except Exception as error:
        return handle_exception(error, config.verbose)
