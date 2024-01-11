from pathlib import Path
from typing import Any, List, Sequence

import click

from ggshield.cmd.iac.scan.all import display_iac_scan_all_result, iac_scan_all
from ggshield.cmd.iac.scan.diff import display_iac_scan_diff_result, iac_scan_diff
from ggshield.cmd.iac.scan.iac_scan_common_options import (
    add_iac_scan_common_options,
    update_context,
)
from ggshield.cmd.iac.scan.iac_scan_utils import augment_unignored_issues
from ggshield.cmd.utils.common_decorators import display_beta_warning, exception_wrapper
from ggshield.cmd.utils.common_options import all_option
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.hooks import check_user_requested_skip
from ggshield.core.git_hooks.prepush import collect_commits_refs
from ggshield.core.scan.scan_mode import ScanMode
from ggshield.utils.git_shell import is_valid_git_commit_ref


@click.command()
@click.argument("prepush_args", nargs=-1, type=click.UNPROCESSED)
@add_iac_scan_common_options()
@all_option
@click.pass_context
@display_beta_warning
@exception_wrapper
def scan_pre_push_cmd(
    ctx: click.Context,
    prepush_args: List[str],
    exit_zero: bool,
    minimum_severity: str,
    ignore_policies: Sequence[str],
    ignore_paths: Sequence[str],
    scan_all: bool,
    **kwargs: Any,
) -> int:
    """
    Scan a Git repository for changes in IaC vulnerabilities in the pushed commits.
    This is intended to be used as a pre-push hook.

    The scan is successful if no *new* IaC vulnerability was found, unless `--all` is used,
    in which case the scan is only successful if no IaC vulnerability (old and new) was found.

    By default, the output will show:
    - The number of known IaC vulnerabilities resolved by the changes
    - The number of known IaC vulnerabilities left untouched
    - The number and the list of new IaC vulnerabilities introduced by the changes
    """
    if check_user_requested_skip():
        return 0

    ctx_obj = ContextObj.get(ctx)
    directory = Path().resolve()
    update_context(ctx, exit_zero, minimum_severity, ignore_policies, ignore_paths)

    _, remote_commit = collect_commits_refs(prepush_args)
    # Will happen if this is the first push on the repo
    has_no_remote_commit = remote_commit is None or not is_valid_git_commit_ref(
        remote_commit
    )

    if scan_all or has_no_remote_commit:
        result = iac_scan_all(ctx, directory, scan_mode=ScanMode.PRE_PUSH_ALL)
        augment_unignored_issues(ctx_obj.config.user_config, result)
        return display_iac_scan_all_result(ctx, directory, result)
    else:
        result = iac_scan_diff(
            ctx,
            directory,
            remote_commit,
            include_staged=False,
            scan_mode=ScanMode.PRE_PUSH_DIFF,
        )
        augment_unignored_issues(ctx_obj.config.user_config, result)
        return display_iac_scan_diff_result(ctx, directory, result)
