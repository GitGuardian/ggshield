from pathlib import Path
from typing import Any, Optional, Sequence, Union

import click
from pygitguardian.iac_models import IaCDiffScanResult, IaCScanParameters

from ggshield.cmd.iac.scan.iac_scan_common_options import (
    add_iac_scan_common_options,
    update_context,
)
from ggshield.cmd.iac.scan.iac_scan_utils import (
    IaCSkipScanResult,
    augment_unignored_issues,
    create_output_handler,
    filter_iac_filepaths,
    get_git_filepaths,
    get_iac_tar,
    handle_scan_error,
)
from ggshield.cmd.utils.common_decorators import display_beta_warning, exception_wrapper
from ggshield.cmd.utils.common_options import (
    directory_argument,
    reference_option,
    staged_option,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.files import check_directory_not_ignored
from ggshield.core import ui
from ggshield.core.git_hooks.ci.supported_ci import SupportedCI
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.core.tar_utils import INDEX_REF, get_empty_tar
from ggshield.utils.files import is_path_excluded
from ggshield.utils.git_shell import (
    Filemode,
    get_diff_files_status,
    get_filepaths_from_ref,
)
from ggshield.verticals.iac.collection.iac_diff_scan_collection import (
    IaCDiffScanCollection,
)
from ggshield.verticals.iac.filter import is_iac_file_path


@click.command()
@add_iac_scan_common_options()
@reference_option
@staged_option
@directory_argument
@click.pass_context
@display_beta_warning
@exception_wrapper
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
    Scan a Git repository for changes in IaC vulnerabilities between two states.

    The scan is successful if no *new* IaC vulnerability was found.

    By default, the output will show:
    - The number of known IaC vulnerabilities resolved by the changes
    - The number of known IaC vulnerabilities left untouched
    - The number and the list of new IaC vulnerabilities introduced by the changes
    """
    if directory is None:
        directory = Path().resolve()
    update_context(ctx, exit_zero, minimum_severity, ignore_policies, ignore_paths)

    result = iac_scan_diff(
        ctx, directory, ref, staged, scan_mode=ScanMode.DIRECTORY_DIFF
    )
    ctx_obj = ContextObj.get(ctx)
    augment_unignored_issues(ctx_obj.config.user_config, result)
    return display_iac_scan_diff_result(ctx, directory, result)


def iac_scan_diff(
    ctx: click.Context,
    directory: Path,
    previous_ref: Optional[str],
    include_staged: bool,
    scan_mode: ScanMode,
    current_ref: Optional[str] = None,
    ci_mode: Optional[SupportedCI] = None,
) -> Union[IaCDiffScanResult, IaCSkipScanResult, None]:
    """
    Performs a diff scan for IaC vulnerabilities,
    comparing two git reference. Vulnerabilities are flagged as new, removed or
    remaining depending on whether they appear in the `current_ref` and `previous_ref`
    git references.

    :param ctx: click.Context with CLI arguments
    :param directory: path to the location we want to scan.
    :param previous_ref: git reference to the state of reference for the analysis
    :param include_staged: bool whether or not we want to consider the staged files
    only when the current reference is set to None.
    :param scan_mode: a string describing the type of scan, for API analytics.
    :param current_ref: optional git reference to the current state, defaults to None.
    When set to None, the current state is the indexed files currently on disk.
    :return: IacDiffScanResult if the scan was performed; IaCSkipScanResult if the scan
    was skipped (i.e. no IaC files were detected or changed between the two references)
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    client = ctx_obj.client
    exclusion_regexes = ctx_obj.exclusion_regexes

    check_directory_not_ignored(directory, exclusion_regexes)

    verbose = ui.is_verbose()

    if verbose:
        if previous_ref is None:
            ui.display_verbose("> No file to scan in reference.")
        else:
            ui.display_verbose(f"> Scanned files in reference {previous_ref}")
            filepaths = filter_iac_filepaths(
                directory, get_git_filepaths(directory, previous_ref)
            )
            for filepath in filepaths:
                ui.display_verbose(f"- {click.format_filename(filepath)}")
            ui.display_verbose("")

    if current_ref is None:
        current_ref = INDEX_REF if include_staged else "HEAD"
    if verbose:
        if include_staged:
            ui.display_verbose("> Scanned files in current state (staged)")
        else:
            ui.display_verbose("> Scanned files in current state")
        filepaths = filter_iac_filepaths(
            directory, get_git_filepaths(directory=directory, ref=current_ref)
        )
        for filepath in filepaths:
            ui.display_verbose(f"- {click.format_filename(filepath)}")

    modified_iac_files = []

    # Check if IaC files were created, deleted or modified
    if previous_ref is None:
        # This means we are scanning all commits up to now.
        filepaths = get_filepaths_from_ref(wd=str(directory), ref=current_ref)
        modified_iac_files = list(filter(is_iac_file_path, filepaths))
    else:
        files_status = get_diff_files_status(
            wd=str(directory),
            current_ref=current_ref,
            ref=previous_ref,
            staged=include_staged,
            similarity=100,
        )
        modified_modes = [Filemode.NEW, Filemode.DELETE, Filemode.MODIFY]
        modified_iac_files = [
            file
            for file, mode in files_status.items()
            if mode in modified_modes
            and not is_path_excluded(file, exclusion_regexes)
            and is_iac_file_path(file)
        ]

    if len(modified_iac_files) == 0:
        return IaCSkipScanResult()

    reference_tar = (
        get_iac_tar(directory, previous_ref, exclusion_regexes)
        if previous_ref is not None
        else get_empty_tar()
    )
    current_tar = get_iac_tar(directory, current_ref, exclusion_regexes)

    scan_parameters = IaCScanParameters(
        list({ignored.policy for ignored in config.user_config.iac.ignored_policies}),
        config.user_config.iac.minimum_severity,
    )

    scan = client.iac_diff_scan(
        reference_tar,
        current_tar,
        scan_parameters,
        ScanContext(
            command_path=ctx.command_path,
            scan_mode=(
                scan_mode if ci_mode is None else f"{scan_mode.value}/{ci_mode.value}"
            ),
            extra_headers={"Ci-Mode": str(ci_mode.value)} if ci_mode else None,
            target_path=directory,
        ).get_http_headers(),
    )

    if not isinstance(scan, IaCDiffScanResult):
        handle_scan_error(client, scan)
        return None
    return scan


def display_iac_scan_diff_result(
    ctx: click.Context,
    directory: Path,
    result: Union[IaCDiffScanResult, IaCSkipScanResult, None],
) -> int:
    output_handler = create_output_handler(ctx)
    if isinstance(result, IaCSkipScanResult):
        return output_handler.process_skip_diff_scan()
    scan = IaCDiffScanCollection(id=str(directory), result=result)
    return output_handler.process_diff_scan(scan)
