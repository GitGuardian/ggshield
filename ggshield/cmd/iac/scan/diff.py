from pathlib import Path
from typing import Any, Optional, Sequence, Union

import click
from pygitguardian.iac_models import IaCDiffScanResult, IaCScanParameters

from ggshield.cmd.iac.scan.iac_scan_common_options import (
    add_iac_scan_common_options,
    directory_argument,
    update_context,
)
from ggshield.cmd.iac.scan.iac_scan_utils import (
    IaCSkipScanResult,
    create_output_handler,
    filter_iac_filepaths,
    get_git_filepaths,
    get_iac_tar,
    handle_scan_error,
)
from ggshield.core.filter import is_filepath_excluded
from ggshield.core.git_shell import INDEX_REF, Filemode, get_diff_files_status
from ggshield.core.text_utils import display_info, display_warning
from ggshield.iac.collection.iac_diff_scan_collection import IaCDiffScanCollection
from ggshield.iac.filter import is_iac_file_path
from ggshield.scan import ScanContext, ScanMode


@click.command()
@add_iac_scan_common_options()
@click.option(
    "--ref",
    required=True,
    type=click.STRING,
    help="A git reference.",
)
@click.option(
    "--staged",
    is_flag=True,
    help="Whether staged changes should be included into the scan.",
)
@directory_argument
@click.pass_context
def scan_diff_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_policies: Sequence[str],
    ignore_paths: Sequence[str],
    ref: str,
    staged: bool,
    directory: Optional[Path],
    **kwargs: Any,
) -> int:
    """
    Scan all changes made since the provided Git ref for IaC vulnerabilities.
    """
    display_warning(
        "This feature is still in beta, its behavior may change in future versions."
    )

    if directory is None:
        directory = Path().resolve()
    update_context(ctx, exit_zero, minimum_severity, ignore_policies, ignore_paths)

    result = iac_scan_diff(ctx, directory, ref, staged)
    output_handler = create_output_handler(ctx)
    if isinstance(result, IaCSkipScanResult):
        return output_handler.process_skip_diff_scan()
    scan = IaCDiffScanCollection(id=str(directory), result=result)
    return output_handler.process_diff_scan(scan)


def iac_scan_diff(
    ctx: click.Context, directory: Path, ref: str, include_staged: bool
) -> Union[IaCDiffScanResult, IaCSkipScanResult, None]:
    config = ctx.obj["config"]
    client = ctx.obj["client"]
    exclusion_regexes = ctx.obj["exclusion_regexes"]

    verbose = config.user_config.verbose if config and config.user_config else False
    if verbose:
        display_info(f"> Scanned files in reference {ref}")
        filepaths = filter_iac_filepaths(directory, get_git_filepaths(directory, ref))
        for filepath in filepaths:
            display_info(f"- {click.format_filename(filepath)}")
        display_info("")

    current_ref = INDEX_REF if include_staged else "HEAD"
    if verbose:
        if include_staged:
            display_info("> Scanned files in current state (staged)")
        else:
            display_info("> Scanned files in current state")
        filepaths = filter_iac_filepaths(
            directory, get_git_filepaths(directory, current_ref)
        )
        for filepath in filepaths:
            display_info(f"- {click.format_filename(filepath)}")

    # Check if IaC files were created, deleted or modified
    files_status = get_diff_files_status(
        wd=str(directory), ref=ref, staged=include_staged, similarity=100
    )
    modified_modes = [Filemode.NEW, Filemode.DELETE, Filemode.MODIFY]
    modified_iac_files = [
        file
        for file, mode in files_status.items()
        if mode in modified_modes
        and not is_filepath_excluded(str(file), exclusion_regexes)
        and is_iac_file_path(file)
    ]

    if len(modified_iac_files) == 0:
        return IaCSkipScanResult()

    reference_tar = get_iac_tar(directory, ref, exclusion_regexes)
    current_tar = get_iac_tar(directory, current_ref, exclusion_regexes)

    scan_parameters = IaCScanParameters(
        config.user_config.iac.ignored_policies, config.user_config.iac.minimum_severity
    )

    scan = client.iac_diff_scan(
        reference_tar,
        current_tar,
        scan_parameters,
        ScanContext(
            command_path=ctx.command_path,
            scan_mode=ScanMode.IAC_DIFF,
        ).get_http_headers(),
    )

    if not scan.success or not isinstance(scan, IaCDiffScanResult):
        handle_scan_error(client, scan)
        return None
    return scan
