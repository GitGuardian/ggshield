from pathlib import Path
from typing import Any, List, Sequence

import click

from ggshield.cmd.common_options import all_option
from ggshield.cmd.sca.scan.sca_scan_utils import (
    create_output_handler,
    display_sca_beta_warning,
    sca_scan_all,
    sca_scan_diff,
)
from ggshield.cmd.sca.scan.scan_common_options import (
    add_sca_scan_common_options,
    update_context,
)
from ggshield.core.git_hooks.prepush import collect_commits_refs
from ggshield.core.utils import EMPTY_SHA
from ggshield.sca.collection.collection import (
    SCAScanAllVulnerabilityCollection,
    SCAScanDiffVulnerabilityCollection,
)


@click.command()
@click.argument("prepush_args", nargs=-1, type=click.UNPROCESSED)
@add_sca_scan_common_options()
@all_option
@click.pass_context
@display_sca_beta_warning
def scan_pre_push_cmd(
    ctx: click.Context,
    prepush_args: List[str],
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
    scan_all: bool,
    **kwargs: Any,
) -> int:
    """
    Scan as pre-push for SCA vulnerabilities.
    By default, it will return vulnerabilities added in the pushed commits.
    """
    directory = Path().resolve()

    # Adds client and required parameters to the context
    update_context(ctx, exit_zero, minimum_severity, ignore_paths)

    _, remote_commit = collect_commits_refs(prepush_args)
    # Will happen if this is the first push on the branch
    has_no_remote_commit = (
        remote_commit is None or "~1" in remote_commit or remote_commit == EMPTY_SHA
    )

    output_handler = create_output_handler(ctx)
    if scan_all or has_no_remote_commit:
        result = sca_scan_all(ctx, directory)
        scan = SCAScanAllVulnerabilityCollection(id=str(directory), result=result)
        return output_handler.process_scan_all_result(scan)

    else:
        result = sca_scan_diff(ctx, directory, remote_commit)
        scan = SCAScanDiffVulnerabilityCollection(id=str(directory), result=result)
        return output_handler.process_scan_diff_result(scan)
