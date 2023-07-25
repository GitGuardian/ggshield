from pathlib import Path
from typing import Any, Optional, Sequence

import click

from ggshield.cmd.common_options import directory_argument
from ggshield.cmd.sca.scan.sca_scan_utils import (
    create_output_handler,
    display_sca_beta_warning,
    sca_scan_all,
)
from ggshield.cmd.sca.scan.scan_common_options import (
    add_sca_scan_common_options,
    update_context,
)
from ggshield.sca.collection.collection import SCAScanAllVulnerabilityCollection


@click.command()
@add_sca_scan_common_options()
@directory_argument
@click.pass_context
@display_sca_beta_warning
def scan_all_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Scan a directory for SCA vulnerabilities.
    """
    if directory is None:
        directory = Path().resolve()

    # Adds client and required parameters to the context
    update_context(ctx, exit_zero, minimum_severity, ignore_paths)

    result = sca_scan_all(ctx, directory)
    scan = SCAScanAllVulnerabilityCollection(id=str(directory), result=result)
    output_handler = create_output_handler(ctx)
    return output_handler.process_scan_all_result(scan)
