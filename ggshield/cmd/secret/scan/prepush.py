import logging
from pathlib import Path
from typing import Any, List

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.hooks import check_user_requested_skip
from ggshield.core.git_hooks.prepush import BYPASS_MESSAGE, collect_commits_refs
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.utils.git_shell import (
    EMPTY_SHA,
    EMPTY_TREE,
    check_git_dir,
    get_list_commit_SHA,
)
from ggshield.verticals.secret.output.messages import remediation_message
from ggshield.verticals.secret.repo import scan_commit_range


logger = logging.getLogger(__name__)


REMEDIATION_STEPS = """  Since the secret was detected before the push BUT after the commit, you need to:
  1. rewrite the git history making sure to replace the secret with its reference (e.g. environment variable).
  2. push again."""


@click.command()
@click.argument("prepush_args", nargs=-1, type=click.UNPROCESSED)
@add_secret_scan_common_options()
@click.pass_context
@exception_wrapper
def prepush_cmd(ctx: click.Context, prepush_args: List[str], **kwargs: Any) -> int:
    """
    Scan as a pre-push git hook all commits that are about to be pushed.
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config

    if check_user_requested_skip():
        return 0

    local_commit, remote_commit = collect_commits_refs(prepush_args)
    logger.debug("refs=(%s, %s)", local_commit, remote_commit)

    if local_commit == EMPTY_SHA:
        click.echo("Deletion event or nothing to scan.", err=True)
        return 0

    if remote_commit == EMPTY_SHA:
        click.echo(
            f"New tree event. Scanning last {config.user_config.max_commits_for_hook} commits.",
            err=True,
        )
        before = EMPTY_TREE
        after = local_commit
        cmd_range = f"{EMPTY_TREE} {local_commit}"
    else:
        before = remote_commit
        after = local_commit
        cmd_range = f"{remote_commit}...{local_commit}"

    commit_list = get_list_commit_SHA(
        cmd_range, max_count=config.user_config.max_commits_for_hook + 1
    )

    if not commit_list:
        click.echo(
            "Unable to get commit range.\n"
            f"  before: {before}\n"
            f"  after: {after}\n"
            "Skipping pre-push hook\n",
            err=True,
        )
        return 0

    if len(commit_list) > config.user_config.max_commits_for_hook:
        click.echo(
            f"Too many commits. Scanning last {config.user_config.max_commits_for_hook} commits\n",
            err=True,
        )
        commit_list = commit_list[-config.user_config.max_commits_for_hook :]

    if config.user_config.verbose:
        click.echo(f"Commits to scan: {len(commit_list)}", err=True)

    check_git_dir()

    scan_context = ScanContext(
        scan_mode=ScanMode.PRE_PUSH,
        command_path=ctx.command_path,
        target_path=Path.cwd(),
    )

    return_code = scan_commit_range(
        client=ctx_obj.client,
        cache=ctx_obj.cache,
        ui=ctx_obj.ui,
        commit_list=commit_list,
        output_handler=create_output_handler(ctx),
        exclusion_regexes=ctx_obj.exclusion_regexes,
        matches_ignore=config.user_config.secret.ignored_matches,
        scan_context=scan_context,
        ignored_detectors=config.user_config.secret.ignored_detectors,
    )
    if return_code:
        click.echo(
            remediation_message(
                remediation_steps=REMEDIATION_STEPS,
                bypass_message=BYPASS_MESSAGE,
                rewrite_git_history=True,
            ),
            err=True,
        )
    return return_code
