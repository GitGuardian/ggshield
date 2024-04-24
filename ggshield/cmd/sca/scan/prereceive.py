import logging
from pathlib import Path
from typing import Any, Sequence

import click
from pygitguardian.sca_models import SCAScanAllOutput

from ggshield.cmd.sca.scan.sca_scan_utils import create_output_handler, sca_scan_diff
from ggshield.cmd.sca.scan.scan_common_options import (
    add_sca_scan_common_options,
    update_context,
)
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.common_options import all_option
from ggshield.core.git_hooks.prereceive import get_breakglass_option, parse_stdin
from ggshield.core.scan.scan_mode import ScanMode
from ggshield.utils.git_shell import EMPTY_TREE, check_git_ref, is_valid_git_commit_ref
from ggshield.verticals.sca.collection.collection import (
    SCAScanAllVulnerabilityCollection,
    SCAScanDiffVulnerabilityCollection,
)


logger = logging.getLogger(__name__)

REMEDIATION_MESSAGE = """  A pre-receive hook set server side prevents you from pushing SCA vulnerabilities.
Apply the recommended remediation steps to remove the vulnerability."""


@click.command()
@add_sca_scan_common_options()
@all_option
@click.pass_context
@exception_wrapper
def scan_pre_receive_cmd(
    ctx: click.Context,
    scan_all: bool,
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
    ignore_fixable: bool,
    ignore_not_fixable: bool,
    **kwargs: Any,
) -> int:
    """
    Scans if the received HEAD of a git repository introduces new SCA vulnerabilities.

    This command checks if the current HEAD of a git repository introduces new SCA
    vulnerabilities compared to the remote HEAD of the branch in a pre-receive hook.

    Scanning a repository with this command will not trigger any incident on your dashboard.

    Only metadata such as call time, request size and scan mode is stored server-side.
    """
    if get_breakglass_option():
        return 0

    before_after = parse_stdin()
    if before_after is None:
        return 0
    else:
        before, after = before_after

    update_context(
        ctx,
        exit_zero,
        minimum_severity,
        ignore_paths,
        ignore_fixable,
        ignore_not_fixable,
    )

    if scan_all:
        # In the pre-receive context, we do not have access to the files,
        # only git objects. Instead of doing an `sca scan all` command,
        # we perform a diff scan with the root of the git tree.
        # Output is handled afterwards, as a scan all.
        before = EMPTY_TREE

    current_path = Path().resolve()

    check_git_ref(wd=str(current_path), ref=after)
    if not is_valid_git_commit_ref(wd=str(current_path), ref=before):
        # When we have a single non-empty commit in the tree,
        # `before` is set to the parent commit which does not exist
        before = None

    result = sca_scan_diff(
        ctx=ctx,
        directory=current_path,
        previous_ref=before,
        include_staged=False,
        current_ref=after,
        scan_mode=ScanMode.PRE_RECEIVE_ALL if scan_all else ScanMode.PRE_RECEIVE_DIFF,
    )

    output_handler = create_output_handler(ctx)

    if scan_all:
        # If we performed a scan all, we can convert the diff scan result to
        # a path scan, extracting the new vulnerabilities.
        result_all = SCAScanAllOutput(
            scanned_files=result.scanned_files,
            found_package_vulns=result.added_vulns,
        )
        scan_all_collection = SCAScanAllVulnerabilityCollection(
            id=str(current_path), result=result_all
        )
        return output_handler.process_scan_all_result(scan_all_collection)

    scan = SCAScanDiffVulnerabilityCollection(id=str(current_path), result=result)
    return output_handler.process_scan_diff_result(scan)
