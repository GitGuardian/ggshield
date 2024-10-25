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
from ggshield.cmd.utils.common_options import directory_argument
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.git_hooks.ci.get_scan_ci_parameters import (
    NotAMergeRequestError,
    get_scan_ci_parameters,
)
from ggshield.core.git_hooks.ci.supported_ci import SupportedCI
from ggshield.core.scan.scan_mode import ScanMode
from ggshield.utils.git_shell import git


@click.command()
@add_iac_scan_common_options()
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
    directory: Optional[Path] = None,
    **kwargs: Any,
) -> int:
    """
    Scan in CI for IaC vulnerabilities. By default, it will return vulnerabilities added in the new commits.

    The scan is successful if no *new* IaC vulnerability was found, unless `--all` is used,
    in which case the scan is only successful if no IaC vulnerability (old and new) was found.
    """
    if directory is None:
        directory = Path().resolve()

    update_context(ctx, exit_zero, minimum_severity, ignore_policies, ignore_paths)
    config = ContextObj.get(ctx).config
    ci_mode = SupportedCI.from_ci_env()

    try:
        # we will work with branch names and deep commits, so we run a git fetch to ensure the
        # branch names and commit sha are locally available
        git(["fetch"], cwd=directory)
        params = get_scan_ci_parameters(ci_mode, wd=directory)
        if params is None:
            ui.display_info("No commit found in merge request, skipping scan.")
            return 0

        current_commit, reference_commit = params

        result = iac_scan_diff(
            ctx,
            directory,
            reference_commit,
            current_ref=current_commit,
            include_staged=True,
            scan_mode=ScanMode.CI_DIFF,
            ci_mode=ci_mode,
        )
        augment_unignored_issues(config.user_config, result)
        return display_iac_scan_diff_result(ctx, directory, result)
    except NotAMergeRequestError:
        ui.display_warning(
            "scan ci expects to be run in a merge-request pipeline.\n"
            "No target branch could be identified, will perform a scan all instead.\n"
            "This is a fallback behaviour, that will be removed in a future version."
        )
        result = iac_scan_all(
            ctx, directory, scan_mode=ScanMode.CI_ALL, ci_mode=ci_mode
        )
        augment_unignored_issues(config.user_config, result)
        return display_iac_scan_all_result(ctx, directory, result)
