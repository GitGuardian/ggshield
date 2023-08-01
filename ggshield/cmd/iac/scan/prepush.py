from pathlib import Path
from typing import Any, List, Sequence

import click

from ggshield.cmd.common_options import all_option
from ggshield.cmd.iac.scan.all import display_iac_scan_all_result, iac_scan_all
from ggshield.cmd.iac.scan.diff import display_iac_scan_diff_result, iac_scan_diff
from ggshield.cmd.iac.scan.iac_scan_common_options import (
    add_iac_scan_common_options,
    update_context,
)
from ggshield.core.git_hooks.prepush import collect_commits_refs
from ggshield.core.text_utils import display_warning
from ggshield.core.utils import EMPTY_SHA


@click.command()
@click.argument("prepush_args", nargs=-1, type=click.UNPROCESSED)
@add_iac_scan_common_options()
@all_option
@click.pass_context
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
    Scan as pre-push for IaC vulnerabilities. By default, it will return vulnerabilities added in the pushed commits.
    """
    display_warning(
        "This feature is still in beta, its behavior may change in future versions."
    )

    directory = Path().resolve()
    update_context(ctx, exit_zero, minimum_severity, ignore_policies, ignore_paths)

    _, remote_commit = collect_commits_refs(prepush_args)
    # Will happen if this is the first push on the branch
    has_no_remote_commit = (
        remote_commit is None or "~1" in remote_commit or remote_commit == EMPTY_SHA
    )

    if scan_all or has_no_remote_commit:
        result = iac_scan_all(ctx, directory)
        return display_iac_scan_all_result(ctx, directory, result)
    else:
        result = iac_scan_diff(ctx, directory, remote_commit, include_staged=False)
        return display_iac_scan_diff_result(ctx, directory, result)
