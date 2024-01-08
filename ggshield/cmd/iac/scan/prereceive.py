import logging
from pathlib import Path
from typing import Any, Sequence

import click
from pygitguardian.iac_models import IaCScanResult

from ggshield.cmd.iac.scan.diff import iac_scan_diff
from ggshield.cmd.iac.scan.iac_scan_common_options import (
    add_iac_scan_common_options,
    update_context,
)
from ggshield.cmd.iac.scan.iac_scan_utils import (
    IaCSkipScanResult,
    augment_unignored_issues,
    create_output_handler,
)
from ggshield.cmd.utils.common_decorators import display_beta_warning, exception_wrapper
from ggshield.cmd.utils.common_options import all_option
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.git_hooks.prereceive import get_breakglass_option, parse_stdin
from ggshield.core.scan.scan_mode import ScanMode
from ggshield.utils.git_shell import EMPTY_TREE, check_git_ref, is_valid_git_commit_ref
from ggshield.verticals.iac.collection.iac_diff_scan_collection import (
    IaCDiffScanCollection,
)
from ggshield.verticals.iac.collection.iac_path_scan_collection import (
    IaCPathScanCollection,
)


logger = logging.getLogger(__name__)

REMEDIATION_MESSAGE = """  A pre-receive hook set server side prevents you from pushing IaC vulnerabilities.
Apply the recommended remediation steps to remove the vulnerability."""


@click.command()
@add_iac_scan_common_options()
@all_option
@click.pass_context
@display_beta_warning
@exception_wrapper
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
    Scan a Git repository for changes in IaC vulnerabilities in the received pushed commits.
    This is intended to be used as a pre-receive hook.

    The scan is successful if no *new* IaC vulnerability was found, unless `--all` is used,
    in which case the scan is only successful if no IaC vulnerability (old and new) was found.

    By default, the output will show:
    - The number of known IaC vulnerabilities resolved by the changes
    - The number of known IaC vulnerabilities left untouched
    - The number and the list of new IaC vulnerabilities introduced by the changes

    It is the remote equivalent of the `iac scan pre-push` command.

    Note that it is not currently possible to scan a specific sub-directory of the repo.
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
        scan_mode=ScanMode.PRE_RECEIVE_ALL if scan_all else ScanMode.PRE_RECEIVE_DIFF,
    )
    augment_unignored_issues(ContextObj.get(ctx).config.user_config, result)

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
