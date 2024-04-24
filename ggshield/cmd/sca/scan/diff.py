from pathlib import Path
from typing import Any, Optional, Sequence

import click

from ggshield.cmd.sca.scan.sca_scan_utils import create_output_handler, sca_scan_diff
from ggshield.cmd.sca.scan.scan_common_options import (
    add_sca_scan_common_options,
    update_context,
)
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.common_options import (
    directory_argument,
    reference_option,
    staged_option,
)
from ggshield.core.scan.scan_mode import ScanMode
from ggshield.verticals.sca.collection.collection import (
    SCAScanDiffVulnerabilityCollection,
)


@click.command()
@add_sca_scan_common_options()
@directory_argument
@reference_option
@staged_option
@click.pass_context
@exception_wrapper
def scan_diff_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
    ignore_fixable: bool,
    ignore_not_fixable: bool,
    ref: str,
    staged: bool,
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Scans if the current revision of a git repository introduces SCA vulnerabilities.

    This command checks if the current revision introduces new vulnerabilities compared
    to the revision from GIT_REF.

    Scanning a repository with this command will not trigger any incident on your
    dashboard.

    Only metadata such as call time, request size and scan mode is stored server-side.
    """
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

    output_handler = create_output_handler(ctx)

    result = sca_scan_diff(
        ctx,
        directory,
        previous_ref=ref,
        include_staged=staged,
        scan_mode=ScanMode.DIFF,
    )
    scan = SCAScanDiffVulnerabilityCollection(id=str(directory), result=result)
    return output_handler.process_scan_diff_result(scan)
