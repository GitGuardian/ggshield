from pathlib import Path
from typing import Any, Optional, Sequence

import click

from ggshield.cmd.iac.scan.diff import iac_scan_diff
from ggshield.cmd.iac.scan.iac_scan_common_options import (
    add_iac_scan_common_options,
    all_option,
    directory_argument,
    update_context,
)
from ggshield.cmd.iac.scan.iac_scan_utils import create_output_handler
from ggshield.core.config.config import Config
from ggshield.core.text_utils import display_warning
from ggshield.iac.collection.iac_diff_scan_collection import IaCDiffScanCollection
from ggshield.iac.iac_scan_models import (
    IaCSkipDiffScanResult,
    create_client_from_config,
)


@click.command()
@add_iac_scan_common_options()
@all_option
@directory_argument
@click.pass_context
def scan_pre_push_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_policies: Sequence[str],
    ignore_paths: Sequence[str],
    all: bool,
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Scan as pre-push for IaC vulnerabilities. By default, it will return vulnerabilities added in the pushed commits.
    """
    display_warning(
        "This feature is still in beta, its behavior may change in future versions."
    )

    # TODO: WIP

    if directory is None:
        directory = Path().resolve()
    update_context(ctx, exit_zero, minimum_severity, ignore_policies, ignore_paths)

    # TODO: remove this once the GGClient is updated with the new diff function
    config: Config = ctx.obj["config"]
    ctx.obj["client"] = create_client_from_config(config)

    ref = "@{upstream}"
    staged = False

    result = iac_scan_diff(ctx, directory, ref, staged)
    output_handler = create_output_handler(ctx)
    if isinstance(result, IaCSkipDiffScanResult):
        return output_handler.process_skip_diff_scan()
    scan = IaCDiffScanCollection(id=str(directory), result=result)
    return output_handler.process_diff_scan(scan)
