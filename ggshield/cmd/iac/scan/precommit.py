from pathlib import Path
from typing import Any, Optional, Sequence

import click

from ggshield.cmd.iac.scan.all import display_iac_scan_all_result, iac_scan_all
from ggshield.cmd.iac.scan.diff import display_iac_scan_diff_result, iac_scan_diff
from ggshield.cmd.iac.scan.iac_scan_common_options import (
    add_iac_scan_common_options,
    update_context,
)
from ggshield.cmd.iac.scan.iac_scan_utils import augment_unignored_issues
from ggshield.cmd.utils.common_decorators import display_beta_warning, exception_wrapper
from ggshield.cmd.utils.common_options import all_option, directory_argument
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.hooks import check_user_requested_skip
from ggshield.core.scan.scan_mode import ScanMode


@click.command()
@add_iac_scan_common_options()
@all_option
@directory_argument
@click.pass_context
@display_beta_warning
@exception_wrapper
def scan_pre_commit_cmd(
    ctx: click.Context,
    exit_zero: bool,
    minimum_severity: str,
    ignore_policies: Sequence[str],
    ignore_paths: Sequence[str],
    scan_all: bool,
    directory: Optional[Path] = None,
    **kwargs: Any,
) -> int:
    """
    Scan a Git repository for changes in IaC vulnerabilities between HEAD and current staged changes.

    The scan is successful if no *new* IaC vulnerability was found, unless `--all` is used,
    in which case the scan is only successful if no IaC vulnerability (old and new) was found.

    By default, the output will show:
    - The number of known IaC vulnerabilities resolved by the changes
    - The number of known IaC vulnerabilities left untouched
    - The number and the list of new IaC vulnerabilities introduced by the changes
    """
    if check_user_requested_skip():
        return 0

    if directory is None:
        directory = Path().resolve()
    ctx_obj = ContextObj.get(ctx)
    update_context(ctx, exit_zero, minimum_severity, ignore_policies, ignore_paths)
    if scan_all:
        result = iac_scan_all(ctx, directory, scan_mode=ScanMode.PRE_COMMIT_ALL)
        augment_unignored_issues(ctx_obj.config.user_config, result)
        return display_iac_scan_all_result(ctx, directory, result)
    result = iac_scan_diff(
        ctx, directory, "HEAD", include_staged=True, scan_mode=ScanMode.PRE_COMMIT_DIFF
    )
    augment_unignored_issues(ctx_obj.config.user_config, result)
    return display_iac_scan_diff_result(ctx, directory, result)
