from pathlib import Path
from typing import Any, Optional, Sequence

import click

from ggshield.cmd.sca.scan.sca_scan_utils import create_output_handler, sca_scan_all
from ggshield.cmd.sca.scan.scan_common_options import (
    add_sca_scan_common_options,
    update_context,
)
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.common_options import directory_argument
from ggshield.verticals.sca.collection.collection import (
    SCAScanAllVulnerabilityCollection,
)


@click.command()
@add_sca_scan_common_options()
@directory_argument
@click.pass_context
@exception_wrapper
def scan_all_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
    ignore_fixable: bool,
    ignore_not_fixable: bool,
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Scans a directory for existing vulnerabilities in open-source dependencies.

    Scanning a repository with this command will not trigger any incident on your dashboard.

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

    result = sca_scan_all(ctx, directory)
    scan = SCAScanAllVulnerabilityCollection(id=str(directory), result=result)
    output_handler = create_output_handler(ctx)
    return output_handler.process_scan_all_result(scan)
