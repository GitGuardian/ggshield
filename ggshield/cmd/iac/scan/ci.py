from pathlib import Path
from typing import Any, Optional, Sequence

import click

from ggshield.cmd.common_options import all_option, directory_argument
from ggshield.cmd.iac.scan.all import display_iac_scan_all_result, iac_scan_all
from ggshield.cmd.iac.scan.diff import display_iac_scan_diff_result, iac_scan_diff
from ggshield.cmd.iac.scan.iac_scan_common_options import (
    add_iac_scan_common_options,
    update_context,
)
from ggshield.core.config import Config
from ggshield.core.git_hooks.ci import collect_commit_range_from_ci_env
from ggshield.core.text_utils import display_warning


@click.command()
@add_iac_scan_common_options()
@all_option
@directory_argument
@click.pass_context
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
    """
    display_warning(
        "This feature is still in beta, its behavior may change in future versions."
    )
    if directory is None:
        directory = Path().resolve()
    update_context(ctx, exit_zero, minimum_severity, ignore_policies, ignore_paths)
    if scan_all:
        result = iac_scan_all(ctx, directory)
        return display_iac_scan_all_result(ctx, directory, result)

    config: Config = ctx.obj["config"]
    commit_list, _ = collect_commit_range_from_ci_env(config.user_config.verbose)
    reference, current_ref = commit_list[0], commit_list[-1]

    # If we failed to fetch a current reference, we set it to HEAD
    if len(commit_list) < 2 or not current_ref:
        current_ref = "HEAD"

    result = iac_scan_diff(
        ctx,
        directory,
        reference,
        current_ref=current_ref,
        include_staged=True,
    )
    return display_iac_scan_diff_result(ctx, directory, result)
