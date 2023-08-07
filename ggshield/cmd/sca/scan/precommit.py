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
from ggshield.sca.collection.collection import (
    SCAScanAllVulnerabilityCollection,
    SCAScanDiffVulnerabilityCollection,
)


@click.command()
@add_sca_scan_common_options()
@all_option
@directory_argument
@click.pass_context
@display_sca_beta_warning
def scan_pre_commit_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
    scan_all: bool,
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Find SCA vulnerabilities in a git working directory, compared to HEAD.
    """
    if directory is None:
        directory = Path().resolve()

    # Adds client and required parameters to the context
    update_context(ctx, exit_zero, minimum_severity, ignore_paths)

    if scan_all:
        result = sca_scan_all(ctx, directory)
        scan = SCAScanAllVulnerabilityCollection(id=str(directory), result=result)
        output_handler = create_output_handler(ctx)
        return output_handler.process_scan_all_result(scan)

    result = sca_scan_diff(
        ctx=ctx, directory=directory, previous_ref="HEAD", include_staged=True
    )

    scan = SCAScanDiffVulnerabilityCollection(id=str(directory), result=result)
    output_handler = create_output_handler(ctx)
    return output_handler.process_scan_diff_result(scan)
