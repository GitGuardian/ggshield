from pathlib import Path
from typing import Any, Optional, Sequence

import click

from ggshield.cmd.sca.scan.sca_scan_utils import create_output_handler, sca_scan_diff
from ggshield.cmd.sca.scan.scan_common_options import (
    add_sca_scan_common_options,
    update_context,
)
from ggshield.cmd.utils.common_decorators import display_beta_warning, exception_wrapper
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
@display_beta_warning
@exception_wrapper
@click.pass_context
def scan_diff_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
    ref: str,
    staged: bool,
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Scan all changes made since the provided Git ref for SCA vulnerabilities.
    """
    if directory is None:
        directory = Path().resolve()

    # Adds client and required parameters to the context
    update_context(ctx, exit_zero, minimum_severity, ignore_paths)

    output_handler = create_output_handler(ctx)

    result = sca_scan_diff(
        ctx,
        directory,
        previous_ref=ref,
        include_staged=staged,
        scan_mode=ScanMode.SCA_DIFF,
    )
    scan = SCAScanDiffVulnerabilityCollection(id=str(directory), result=result)
    return output_handler.process_scan_diff_result(scan)
