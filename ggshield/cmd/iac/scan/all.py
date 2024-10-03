from pathlib import Path
from typing import Any, Optional, Sequence, Union

import click
from pygitguardian.iac_models import IaCScanParameters, IaCScanResult

from ggshield.cmd.iac.scan.iac_scan_common_options import (
    add_iac_scan_common_options,
    update_context,
)
from ggshield.cmd.iac.scan.iac_scan_utils import (
    IaCSkipScanResult,
    augment_unignored_issues,
    create_output_handler,
    handle_scan_error,
)
from ggshield.cmd.utils.common_decorators import display_beta_warning, exception_wrapper
from ggshield.cmd.utils.common_options import directory_argument
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.files import check_directory_not_ignored
from ggshield.core import ui
from ggshield.core.dirs import get_project_root_dir
from ggshield.core.git_hooks.ci.supported_ci import SupportedCI
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.verticals.iac.collection.iac_path_scan_collection import (
    IaCPathScanCollection,
)
from ggshield.verticals.iac.filter import get_iac_files_from_path


# Changes to arguments must be propagated to default_command
@click.command()
@add_iac_scan_common_options()
@directory_argument
@click.pass_context
@display_beta_warning
@exception_wrapper
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

    The scan is successful if no IaC vulnerability (known or new) was found.
    """
    if directory is None:
        directory = Path().resolve()
    update_context(ctx, exit_zero, minimum_severity, ignore_policies, ignore_paths)

    result = iac_scan_all(ctx, directory, scan_mode=ScanMode.DIRECTORY_ALL)
    ctx_obj = ContextObj.get(ctx)
    augment_unignored_issues(ctx_obj.config.user_config, result)
    return display_iac_scan_all_result(ctx, directory, result)


def iac_scan_all(
    ctx: click.Context,
    directory: Path,
    scan_mode: ScanMode,
    ci_mode: Optional[SupportedCI] = None,
) -> Union[IaCScanResult, IaCSkipScanResult, None]:
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config

    check_directory_not_ignored(directory, ctx_obj.exclusion_regexes)

    paths = get_iac_files_from_path(
        path=directory,
        exclusion_regexes=ctx_obj.exclusion_regexes,
        # If the repository is a git repository, ignore untracked files
        ignore_git=False,
        ignore_git_staged=(scan_mode == ScanMode.PRE_PUSH_ALL),
    )

    if not paths:
        return IaCSkipScanResult()

    root = get_project_root_dir(directory)
    relative_paths = [str(x.resolve().relative_to(root)) for x in paths]

    if ui.is_verbose():
        ui.display_verbose("> Scanned files")
        for filepath in relative_paths:
            ui.display_verbose(f"- {click.format_filename(filepath)}")

    client = ctx_obj.client

    scan_parameters = IaCScanParameters(
        list({ignored.policy for ignored in config.user_config.iac.ignored_policies}),
        config.user_config.iac.minimum_severity,
    )
    # If paths are not sorted, the tar bytes order will be different when calling the function twice
    # Different bytes order will cause different tarfile hash_key resulting in a GIM cache bypass.
    relative_paths.sort()
    scan = client.iac_directory_scan(
        root,
        relative_paths,
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

    if not isinstance(scan, IaCScanResult):
        handle_scan_error(client, scan)
        return None
    return scan


def display_iac_scan_all_result(
    ctx: click.Context,
    directory: Path,
    result: Union[IaCScanResult, IaCSkipScanResult, None],
) -> int:
    output_handler = create_output_handler(ctx)

    if isinstance(result, IaCSkipScanResult):
        return output_handler.process_skip_scan()

    scan = IaCPathScanCollection(id=str(directory), result=result)
    return output_handler.process_scan(scan)
