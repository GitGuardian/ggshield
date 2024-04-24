from pathlib import Path
from typing import Any, Optional, Sequence

import click

from ggshield.cmd.sca.scan.sca_scan_utils import (
    create_output_handler,
    sca_scan_all,
    sca_scan_diff,
)
from ggshield.cmd.sca.scan.scan_common_options import (
    add_sca_scan_common_options,
    update_context,
)
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.common_options import all_option, directory_argument
from ggshield.cmd.utils.hooks import check_user_requested_skip
from ggshield.core.scan.scan_mode import ScanMode
from ggshield.verticals.sca.collection.collection import (
    SCAScanAllVulnerabilityCollection,
    SCAScanDiffVulnerabilityCollection,
)


@click.command()
@add_sca_scan_common_options()
@all_option
@directory_argument
@click.pass_context
@exception_wrapper
def scan_pre_commit_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
    ignore_fixable: bool,
    ignore_not_fixable: bool,
    scan_all: bool,
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Scans if the currently staged files introduce SCA vulnerabilities.

    This command checks if the currently staged files introduce SCA vulnerabilities
    compared to the current state of the repository.

    Scanning a repository with this command will not trigger any incident on your dashboard.

    Only metadata such as call time, request size and scan mode is stored server-side.
    """
    if check_user_requested_skip():
        return 0

    if directory is None:
        directory = Path().resolve()

    # Adds client and required parameters to the context
    update_context(
        ctx,
        exit_zero,
        minimum_severity,
        ignore_paths,
        ignore_fixable,
        ignore_not_fixable,
    )

    if scan_all:
        result = sca_scan_all(ctx, directory, scan_mode=ScanMode.PRE_COMMIT_ALL)
        scan = SCAScanAllVulnerabilityCollection(id=str(directory), result=result)
        output_handler = create_output_handler(ctx)
        return output_handler.process_scan_all_result(scan)

    result = sca_scan_diff(
        ctx=ctx,
        directory=directory,
        previous_ref="HEAD",
        include_staged=True,
        scan_mode=ScanMode.PRE_COMMIT_DIFF,
    )

    scan = SCAScanDiffVulnerabilityCollection(id=str(directory), result=result)
    output_handler = create_output_handler(ctx)
    return output_handler.process_scan_diff_result(scan)
