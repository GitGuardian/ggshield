import logging
import multiprocessing
import os
import sys
from pathlib import Path
from typing import Any, List, Pattern, Set

import click
from pygitguardian import GGClient

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.cache import ReadOnlyCache
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.errors import ExitCode, handle_exception
from ggshield.core.git_hooks.prereceive import (
    get_breakglass_option,
    get_prereceive_timeout,
    parse_stdin,
)
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.utils.git_shell import get_list_commit_SHA
from ggshield.verticals.secret.output import (
    SecretGitLabWebUIOutputHandler,
    SecretOutputHandler,
)
from ggshield.verticals.secret.repo import scan_commit_range


logger = logging.getLogger(__name__)


def _execute_prereceive(
    config: Config,
    output_handler: SecretOutputHandler,
    commit_list: List[str],
    command_path: str,
    client: GGClient,
    exclusion_regexes: Set[Pattern[str]],
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
            commit_list=commit_list,
            output_handler=output_handler,
            exclusion_regexes=exclusion_regexes,
            secret_config=config.user_config.secret,
            scan_context=scan_context,
        )
        if return_code:
            ui.display_info(
                config.user_config.secret.prereceive_remediation_message
                or client.remediation_messages.pre_receive
            )
        sys.exit(return_code)
    except Exception as error:
        sys.exit(handle_exception(error))


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
    ctx_obj.client = create_client_from_config(ctx_obj.config)
    config = ctx_obj.config
    output_handler = create_output_handler(ctx)
    if os.getenv("GL_PROTOCOL") == "web":
        # We are inside GitLab web UI
        output_handler = SecretGitLabWebUIOutputHandler(
            secret_config=config.user_config.secret, verbose=False
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
        ui.display_info(
            f"Too many commits. Scanning last {config.user_config.max_commits_for_hook} commits\n",
        )
        commit_list = commit_list[-config.user_config.max_commits_for_hook :]

    ui.display_verbose(f"Commits to scan: {len(commit_list)}")

    process = multiprocessing.Process(
        target=_execute_prereceive,
        kwargs={
            "config": config,
            "output_handler": output_handler,
            "commit_list": commit_list,
            "command_path": ctx.command_path,
            "client": ctx_obj.client,
            "exclusion_regexes": ctx_obj.exclusion_regexes,
        },
    )

    process.start()
    process.join(timeout=get_prereceive_timeout())
    if process.is_alive() or process.exitcode is None:
        ui.display_error("\nPre-receive hook took too long")
        process.kill()
        return 0
    if process.exitcode == ExitCode.GITGUARDIAN_SERVER_UNAVAILABLE:
        ui.display_error("\nGitGuardian server is not responding. Skipping checks.")
        return 0

    return process.exitcode
