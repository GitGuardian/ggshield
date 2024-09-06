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
from ggshield.core.scan import Commit, ScanContext, ScanMode
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
    "--skip-unchanged-merge-files",
    is_flag=True,
    help="When scanning a merge commit, skip files that were not modified by the merge"
    " (assumes the merged commits are secret free).",
)
@click.argument("precommit_args", nargs=-1, type=click.UNPROCESSED)
@add_secret_scan_common_options()
@click.pass_context
@exception_wrapper
def precommit_cmd(
    ctx: click.Context,
    skip_unchanged_merge_files: bool,
    precommit_args: List[str],
    **kwargs: Any,
) -> int:  # pragma: no cover
    """
    Scan as a pre-commit hook all changes that have been staged in a git repository.
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    verbose = config.user_config.verbose

    if check_user_requested_skip():
        return 0

    output_handler = SecretTextOutputHandler(
        show_secrets=config.user_config.secret.show_secrets,
        verbose=verbose,
        client=ctx_obj.client,
        output=None,
        ignore_known_secrets=config.user_config.secret.ignore_known_secrets,
        with_incident_details=config.user_config.secret.with_incident_details,
    )
    check_git_dir()

    scan_context = ScanContext(
        scan_mode=ScanMode.PRE_COMMIT,
        command_path=ctx.command_path,
        target_path=Path.cwd(),
    )

    # Get the commit object
    if skip_unchanged_merge_files and check_is_merge_with_conflict(Path.cwd()):
        commit = Commit.from_merge(ctx_obj.exclusion_regexes)
    elif skip_unchanged_merge_files and check_is_merge_without_conflict():
        merge_branch = get_merge_branch_from_reflog()
        commit = Commit.from_merge(ctx_obj.exclusion_regexes, merge_branch)
    else:
        commit = Commit.from_staged(ctx_obj.exclusion_regexes)

    scanner = SecretScanner(
        client=ctx_obj.client,
        cache=ctx_obj.cache,
        scan_context=scan_context,
        ignored_matches=config.user_config.secret.ignored_matches,
        ignored_detectors=config.user_config.secret.ignored_detectors,
    )
    with ctx_obj.ui.create_scanner_ui(len(commit.urls), verbose=verbose) as scanner_ui:
        results = scanner.scan(commit.get_files(), scanner_ui)

    return_code = output_handler.process_scan(
        SecretScanCollection(id="cached", type="pre-commit", results=results)
    )
    if return_code:
        click.echo(
            ctx_obj.client.remediation_messages.pre_commit,
            err=True,
        )
    return return_code
