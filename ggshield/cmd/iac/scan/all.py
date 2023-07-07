from pathlib import Path
from typing import Any, Optional, Sequence, Union

import click
from pygitguardian.iac_models import IaCScanParameters, IaCScanResult

from ggshield.cmd.iac.scan.iac_scan_common_options import (
    add_iac_scan_common_options,
    directory_argument,
    update_context,
)
from ggshield.cmd.iac.scan.iac_scan_utils import (
    IaCSkipScanResult,
    create_output_handler,
    handle_scan_error,
)
from ggshield.iac.collection.iac_path_scan_collection import IaCPathScanCollection
from ggshield.iac.filter import get_iac_files_from_path
from ggshield.scan import ScanContext, ScanMode


# Changes to arguments must be propagated to default_command
@click.command()
@add_iac_scan_common_options()
@directory_argument
@click.pass_context
def scan_all_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_policies: Sequence[str],
    ignore_paths: Sequence[str],
    directory: Optional[Path] = None,
    **kwargs: Any,
) -> int:
    """
    Scan a directory for all IaC vulnerabilities in the current state.
    """
    if directory is None:
        directory = Path().resolve()
    update_context(ctx, exit_zero, minimum_severity, ignore_policies, ignore_paths)

    result = iac_scan_all(ctx, directory)
    return display_iac_scan_all_result(ctx, directory, result)


def iac_scan_all(
    ctx: click.Context, directory: Path
) -> Union[IaCScanResult, IaCSkipScanResult, None]:
    paths = get_iac_files_from_path(
        path=directory,
        exclusion_regexes=ctx.obj["exclusion_regexes"],
        verbose=ctx.obj["config"].verbose,
        # If the repository is a git repository, ignore untracked files
        ignore_git=False,
    )

    if not paths:
        return IaCSkipScanResult()

    config = ctx.obj["config"]
    client = ctx.obj["client"]

    scan_parameters = IaCScanParameters(
        config.user_config.iac.ignored_policies, config.user_config.iac.minimum_severity
    )

    scan = client.iac_directory_scan(
        directory,
        paths,
        scan_parameters,
        ScanContext(
            command_path=ctx.command_path,
            scan_mode=ScanMode.IAC_DIRECTORY,
        ).get_http_headers(),
    )

    if not scan.success or not isinstance(scan, IaCScanResult):
        handle_scan_error(client, scan)
        return None
    return scan


def display_iac_scan_all_result(
    ctx: click.Context,
    directory: Path,
    result: Optional[IaCScanResult],
) -> int:
    output_handler = create_output_handler(ctx)

    if isinstance(result, IaCSkipScanResult):
        return output_handler.process_skip_scan()

    scan = IaCPathScanCollection(id=str(directory), result=result)
    return output_handler.process_scan(scan)
