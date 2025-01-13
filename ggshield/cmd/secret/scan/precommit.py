import os
import subprocess
from pathlib import Path
from typing import Any, List

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
)
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.hooks import check_user_requested_skip
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.scan import Commit, ScanContext, ScanMode
from ggshield.core.scanner_ui import create_scanner_ui
from ggshield.utils.git_shell import check_git_dir, git
from ggshield.verticals.secret import SecretScanCollection, SecretScanner
from ggshield.verticals.secret.output import SecretTextOutputHandler


def check_is_merge_without_conflict() -> bool:
    """Check if the reflog action is a merge without conflict"""
    return os.getenv("GIT_REFLOG_ACTION", "").split(" ")[0] == "merge"


def get_merge_branch_from_reflog() -> str:
    """Get the branch that was merged from the reflog"""
    return os.getenv("GIT_REFLOG_ACTION", "").split(" ")[-1]


def check_is_merge_with_conflict(cwd: Path) -> bool:
    """Check if MERGE_HEAD exists  (meaning we are in a merge with conflict)"""
    try:
        git(["rev-parse", "--verify", "-q", "MERGE_HEAD"], cwd=cwd)
        # MERGE_HEAD exists
        return True
    except subprocess.CalledProcessError:
        # MERGE_HEAD does not exist
        return False


@click.command()
@click.option(
    "--scan-all-merge-files",
    is_flag=True,
    help="When scanning a merge commit, scan all files, including those that merged without conflicts.",
)
@click.argument("precommit_args", nargs=-1, type=click.UNPROCESSED)
@add_secret_scan_common_options()
@click.pass_context
@exception_wrapper
def precommit_cmd(
    ctx: click.Context,
    scan_all_merge_files: bool,
    precommit_args: List[str],
    **kwargs: Any,
) -> int:  # pragma: no cover
    """
    Scan as a pre-commit hook all changes that have been staged in a git repository.
    """
    ctx_obj = ContextObj.get(ctx)
    ctx_obj.client = create_client_from_config(ctx_obj.config)
    config = ctx_obj.config

    if check_user_requested_skip():
        return 0

    output_handler = SecretTextOutputHandler(
        verbose=ui.is_verbose(),
        client=ctx_obj.client,
        output=None,
        secret_config=config.user_config.secret,
    )
    check_git_dir()

    scan_context = ScanContext(
        scan_mode=ScanMode.PRE_COMMIT,
        command_path=ctx.command_path,
        target_path=Path.cwd(),
    )

    # Get the commit object
    if not scan_all_merge_files and check_is_merge_with_conflict(Path.cwd()):
        commit = Commit.from_merge(ctx_obj.exclusion_regexes)
    elif not scan_all_merge_files and check_is_merge_without_conflict():
        merge_branch = get_merge_branch_from_reflog()
        commit = Commit.from_merge(ctx_obj.exclusion_regexes, merge_branch)
    else:
        commit = Commit.from_staged(ctx_obj.exclusion_regexes)

    scanner = SecretScanner(
        client=ctx_obj.client,
        cache=ctx_obj.cache,
        scan_context=scan_context,
        secret_config=config.user_config.secret,
    )
    with create_scanner_ui(len(commit.urls)) as scanner_ui:
        results = scanner.scan(commit.get_files(), scanner_ui)

    return_code = output_handler.process_scan(
        SecretScanCollection(id="cached", type="pre-commit", results=results)
    )
    if return_code:
        ui.display_info(ctx_obj.client.remediation_messages.pre_commit)
    return return_code
