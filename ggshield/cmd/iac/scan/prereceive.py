import logging
from pathlib import Path
from typing import Any, Sequence

import click
from pygitguardian.iac_models import IaCScanResult

from ggshield.cmd.common_options import all_option
from ggshield.cmd.iac.scan.diff import iac_scan_diff
from ggshield.cmd.iac.scan.iac_scan_common_options import (
    add_iac_scan_common_options,
    update_context,
)
from ggshield.cmd.iac.scan.iac_scan_utils import (
    IaCSkipScanResult,
    create_output_handler,
)
from ggshield.core.git_hooks.prereceive import get_breakglass_option, parse_stdin
from ggshield.core.git_shell import check_git_ref, is_valid_git_commit_ref
from ggshield.core.utils import EMPTY_TREE
from ggshield.iac.collection.iac_diff_scan_collection import IaCDiffScanCollection
from ggshield.iac.collection.iac_path_scan_collection import IaCPathScanCollection


logger = logging.getLogger(__name__)

REMEDIATION_MESSAGE = """  A pre-receive hook set server side prevents you from pushing IaC vulnerabilities.
Apply the recommended remediation steps to remove the vulnerability."""


@click.command()
@add_iac_scan_common_options()
@all_option
@click.pass_context
def scan_pre_receive_cmd(
    ctx: click.Context,
    scan_all: bool,
    exit_zero: bool,
    minimum_severity: str,
    ignore_policies: Sequence[str],
    ignore_paths: Sequence[str],
    **kwargs: Any,
) -> int:
    """
    scan as a pre-receive git hook.
    """
    if get_breakglass_option():
        return 0

    before_after = parse_stdin()
    if before_after is None:
        return 0
    else:
        before, after = before_after

    update_context(ctx, exit_zero, minimum_severity, ignore_policies, ignore_paths)

    if scan_all:
        # In the pre-receive context, we do not have access to the files,
        # only git objects. Instead of doing an `iac scan all` command,
        # we perform a diff scan with the root of the git tree.
        # Output is handled afterwards, as a scan all.
        before = EMPTY_TREE

    current_path = Path().resolve()

    check_git_ref(wd=str(current_path), ref=after)
    if not is_valid_git_commit_ref(wd=str(current_path), ref=before):
        # When we have a single non-empty commit in the tree,
        # `before` is set to the parent commit which does not exist
        before = None

    result = iac_scan_diff(
        ctx=ctx,
        directory=current_path,
        previous_ref=before,
        include_staged=False,
        current_ref=after,
    )

    output_handler = create_output_handler(ctx)

    if isinstance(result, IaCSkipScanResult):
        return output_handler.process_skip_diff_scan()

    scan = IaCDiffScanCollection(id=str(current_path), result=result)

    if result is not None:
        if scan_all:
            # If we performed a scan all, we can convert the diff scan result to
            # a path scan, extracting the new vulnerabilities.
            result_all = IaCScanResult(
                id=result.id,
                iac_engine_version=result.iac_engine_version,
                entities_with_incidents=result.entities_with_incidents.new,
            )
            result_all.status_code = result.status_code
            scan_all_collection = IaCPathScanCollection(
                id=str(current_path), result=result_all
            )
            return output_handler.process_scan(scan_all_collection)

    return output_handler.process_diff_scan(scan)
