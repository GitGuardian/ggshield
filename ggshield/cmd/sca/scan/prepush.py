from pathlib import Path
from typing import Any, List, Sequence

import click

from ggshield.cmd.sca.scan.sca_scan_utils import (
    create_output_handler,
    sca_scan_all,
    sca_scan_diff,
)
from ggshield.cmd.sca.scan.scan_common_options import (
    add_sca_scan_common_options,
    update_context,
)
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.common_options import all_option
from ggshield.cmd.utils.hooks import check_user_requested_skip
from ggshield.core.git_hooks.prepush import collect_commits_refs
from ggshield.core.scan.scan_mode import ScanMode
from ggshield.utils.git_shell import EMPTY_SHA
from ggshield.verticals.sca.collection.collection import (
    SCAScanAllVulnerabilityCollection,
    SCAScanDiffVulnerabilityCollection,
)


@click.command()
@click.argument("prepush_args", nargs=-1, type=click.UNPROCESSED)
@add_sca_scan_common_options()
@all_option
@click.pass_context
@exception_wrapper
def scan_pre_push_cmd(
    ctx: click.Context,
    prepush_args: List[str],
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
    ignore_fixable: bool,
    ignore_not_fixable: bool,
    scan_all: bool,
    **kwargs: Any,
) -> int:
    """
    Scans if the local HEAD of a git repository introduces new SCA vulnerabilities.

    This command checks if the current HEAD of a git repository introduces new SCA
    vulnerabilities compared to the remote HEAD of the branch in a pre-push hook.

    Scanning a repository with this command will not trigger any incident on your dashboard.

    Only metadata such as call time, request size and scan mode is stored server-side.
    """
    if check_user_requested_skip():
        return 0

    directory = Path().resolve()

    # Adds client and required parameters to the context
    update_context(
        ctx,
        exit_zero,
        minimum_severity,
        ignore_paths,
        ignore_fixable,
        ignore_not_fixable,
    )

    _, remote_commit = collect_commits_refs(prepush_args)
    # Will happen if this is the first push on the branch
    has_no_remote_commit = (
        remote_commit is None or "~1" in remote_commit or remote_commit == EMPTY_SHA
    )

    output_handler = create_output_handler(ctx)
    if scan_all or has_no_remote_commit:
        result = sca_scan_all(ctx, directory, scan_mode=ScanMode.PRE_PUSH_ALL)
        scan = SCAScanAllVulnerabilityCollection(id=str(directory), result=result)
        return output_handler.process_scan_all_result(scan)

    else:
        result = sca_scan_diff(
            ctx, directory, previous_ref=remote_commit, scan_mode=ScanMode.PRE_PUSH_DIFF
        )
        scan = SCAScanDiffVulnerabilityCollection(id=str(directory), result=result)
        return output_handler.process_scan_diff_result(scan)
