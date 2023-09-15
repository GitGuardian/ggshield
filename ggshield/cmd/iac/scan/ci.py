from pathlib import Path
from typing import Any, Optional, Sequence

import click

from ggshield.cmd.iac.scan.all import display_iac_scan_all_result, iac_scan_all
from ggshield.cmd.iac.scan.diff import display_iac_scan_diff_result, iac_scan_diff
from ggshield.cmd.iac.scan.iac_scan_common_options import (
    add_iac_scan_common_options,
    update_context,
)
from ggshield.cmd.utils.common_decorators import display_beta_warning, exception_wrapper
from ggshield.cmd.utils.common_options import all_option, directory_argument
from ggshield.core.config import Config
from ggshield.core.git_hooks.ci import get_current_and_previous_state_from_ci_env


@click.command()
@add_iac_scan_common_options()
@all_option
@directory_argument
@click.pass_context
@display_beta_warning
@exception_wrapper
def scan_ci_cmd(
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
    Scan in CI for IaC vulnerabilities. By default, it will return vulnerabilities added in the new commits.

    The scan is successful if no *new* IaC vulnerability was found, unless `--all` is used,
    in which case the scan is only successful if no IaC vulnerability (old and new) was found.
    """
    config: Config = ctx.obj["config"]
    if directory is None:
        directory = Path().resolve()
    update_context(ctx, exit_zero, minimum_severity, ignore_policies, ignore_paths)
    if scan_all:
        result = iac_scan_all(ctx, directory)
        return display_iac_scan_all_result(ctx, directory, result)

    current_commit, previous_commit = get_current_and_previous_state_from_ci_env(
        config.user_config.verbose
    )

    result = iac_scan_diff(
        ctx,
        directory,
        previous_commit,
        current_ref=current_commit,
        include_staged=True,
    )
    return display_iac_scan_diff_result(ctx, directory, result)
