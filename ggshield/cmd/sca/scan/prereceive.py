import logging
from pathlib import Path
from typing import Any, Sequence

import click

from ggshield.cmd.common_options import all_option
from ggshield.cmd.sca.scan.sca_scan_utils import (
    create_output_handler,
    display_sca_beta_warning,
    sca_scan_diff,
)
from ggshield.cmd.sca.scan.scan_common_options import (
    add_sca_scan_common_options,
    update_context,
)
from ggshield.core.git_hooks.prereceive import get_breakglass_option, parse_stdin
from ggshield.core.git_shell import check_git_ref, is_valid_git_commit_ref
from ggshield.core.utils import EMPTY_TREE
from ggshield.sca.collection.collection import (
    SCAScanAllVulnerabilityCollection,
    SCAScanDiffVulnerabilityCollection,
)
from ggshield.sca.sca_scan_models import SCAScanAllOutput


logger = logging.getLogger(__name__)

REMEDIATION_MESSAGE = """  A pre-receive hook set server side prevents you from pushing SCA vulnerabilities.
Apply the recommended remediation steps to remove the vulnerability."""


@click.command()
@add_sca_scan_common_options()
@all_option
@click.pass_context
@display_sca_beta_warning
def scan_pre_receive_cmd(
    ctx: click.Context,
    scan_all: bool,
    exit_zero: bool,
    minimum_severity: str,
    ignore_paths: Sequence[str],
    **kwargs: Any,
) -> int:
    """
    Scan as a pre-receive git hook.
    """
    if get_breakglass_option():
        return 0

    before_after = parse_stdin()
    if before_after is None:
        return 0
    else:
        before, after = before_after

    update_context(ctx, exit_zero, minimum_severity, ignore_paths)

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
