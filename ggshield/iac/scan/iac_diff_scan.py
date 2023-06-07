from pathlib import Path
from typing import Optional

import click
from pygitguardian.iac_models import IaCScanParameters

from ggshield.core.git_shell import INDEX_REF
from ggshield.iac.collection.iac_diff_scan_collection import IaCDiffScanCollection
from ggshield.iac.iac_scan_models import IaCDiffScanResult, mock_api_iac_diff_scan
from ggshield.iac.scan.iac_scan_utils import (
    create_output_handler,
    get_iac_tar,
    handle_scan_error,
)
from ggshield.scan import ScanContext, ScanMode


def execute_iac_diff_scan(
    ctx: click.Context, directory: Path, since: str, include_staged: bool
) -> int:
    result = iac_diff_scan(ctx, directory, since, include_staged)
    scan = IaCDiffScanCollection(id=str(directory), result=result)
    output_handler = create_output_handler(ctx)
    return output_handler.process_diff_scan(scan)


def iac_diff_scan(
    ctx: click.Context, directory: Path, since: str, include_staged: bool
) -> Optional[IaCDiffScanResult]:
    config = ctx.obj["config"]
    client = ctx.obj["client"]

    reference_tar = get_iac_tar(directory, since)
    current_ref = INDEX_REF if include_staged else "HEAD"
    current_tar = get_iac_tar(directory, current_ref)

    scan_parameters = IaCScanParameters(
        config.user_config.iac.ignored_policies, config.user_config.iac.minimum_severity
    )

    scan = mock_api_iac_diff_scan(
        client,
        reference_tar,
        current_tar,
        scan_parameters,
        ScanContext(
            command_path=ctx.command_path,
            scan_mode=ScanMode.IAC_DIRECTORY,
        ).get_http_headers(),
    )

    if not scan.success or not isinstance(scan, IaCDiffScanResult):
        handle_scan_error(client, scan)
        return None
    return scan
