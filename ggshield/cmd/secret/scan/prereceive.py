import logging
import multiprocessing
import os
import re
import sys
from pathlib import Path
from typing import Any, List, Set

import click
from pygitguardian import GGClient

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.cache import ReadOnlyCache
from ggshield.core.config import Config
from ggshield.core.errors import handle_exception
from ggshield.core.git_hooks.prereceive import (
    BYPASS_MESSAGE,
    get_breakglass_option,
    get_prereceive_timeout,
    parse_stdin,
)
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.core.text_utils import display_error
from ggshield.core.ui.ggshield_ui import GGShieldUI
from ggshield.utils.git_shell import get_list_commit_SHA
from ggshield.verticals.secret.output import (
    SecretGitLabWebUIOutputHandler,
    SecretOutputHandler,
)
from ggshield.verticals.secret.output.messages import remediation_message
from ggshield.verticals.secret.repo import scan_commit_range


logger = logging.getLogger(__name__)


REMEDIATION_MESSAGE = """  A pre-receive hook set server side prevented you from pushing secrets.
  Since the secret was detected during the push BUT after the commit, you need to:
  1. rewrite the git history making sure to replace the secret with its reference (e.g. environment variable).
  2. push again."""


def _execute_prereceive(
    config: Config,
    output_handler: SecretOutputHandler,
    commit_list: List[str],
    command_path: str,
    client: GGClient,
    ui: GGShieldUI,
    exclusion_regexes: Set[re.Pattern],
) -> None:
    try:
        scan_context = ScanContext(
            scan_mode=ScanMode.PRE_RECEIVE,
            command_path=command_path,
            target_path=Path.cwd(),
        )

        return_code = scan_commit_range(
            client=client,
            cache=ReadOnlyCache(),
            ui=ui,
            commit_list=commit_list,
            output_handler=output_handler,
            exclusion_regexes=exclusion_regexes,
            matches_ignore=config.user_config.secret.ignored_matches,
            scan_context=scan_context,
            ignored_detectors=config.user_config.secret.ignored_detectors,
        )
        if return_code:
            click.echo(
                remediation_message(
                    remediation_steps=REMEDIATION_MESSAGE,
                    bypass_message=BYPASS_MESSAGE,
                    rewrite_git_history=True,
                ),
                err=True,
            )
        sys.exit(return_code)
    except Exception as error:
        sys.exit(handle_exception(error, config.user_config.verbose))


@click.command()
@click.argument("prereceive_args", nargs=-1, type=click.UNPROCESSED)
@click.option(
    "--web",
    is_flag=True,
    default=None,
    help="Deprecated.",
    hidden=True,
)
@add_secret_scan_common_options()
@click.pass_context
def prereceive_cmd(
    ctx: click.Context, web: bool, prereceive_args: List[str], **kwargs: Any
) -> int:
    """
    Scan as a pre-receive git hook all commits about to enter the remote git repository.
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    output_handler = create_output_handler(ctx)
    if os.getenv("GL_PROTOCOL") == "web":
        # We are inside GitLab web UI
        output_handler = SecretGitLabWebUIOutputHandler(
            show_secrets=config.user_config.secret.show_secrets,
            ignore_known_secrets=config.user_config.secret.ignore_known_secrets,
        )

    if get_breakglass_option():
        return 0

    before_after = parse_stdin()
    if before_after is None:
        return 0
    else:
        before, after = before_after

    commit_list = get_list_commit_SHA(
        f"{before}...{after}", max_count=config.user_config.max_commits_for_hook + 1
    )

    assert commit_list, "Commit list should not be empty at this point"

    if len(commit_list) > config.user_config.max_commits_for_hook:
        click.echo(
            f"Too many commits. Scanning last {config.user_config.max_commits_for_hook} commits\n",
            err=True,
        )
        commit_list = commit_list[-config.user_config.max_commits_for_hook :]

    if config.user_config.verbose:
        click.echo(f"Commits to scan: {len(commit_list)}", err=True)

    process = multiprocessing.Process(
        target=_execute_prereceive,
        kwargs={
            "config": config,
            "output_handler": output_handler,
            "commit_list": commit_list,
            "command_path": ctx.command_path,
            "client": ctx_obj.client,
            "ui": ctx_obj.ui,
            "exclusion_regexes": ctx_obj.exclusion_regexes,
        },
    )

    process.start()
    process.join(timeout=get_prereceive_timeout())
    if process.is_alive() or process.exitcode is None:
        display_error("\nPre-receive hook took too long")
        process.kill()
        return 0

    return process.exitcode
