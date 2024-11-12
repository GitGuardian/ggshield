from pathlib import Path
from typing import Any

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.core.text_utils import pluralize
from ggshield.utils.git_shell import (
    check_git_dir,
    get_default_branch,
    get_list_commit_SHA,
)
from ggshield.verticals.secret.repo import scan_commit_range


@click.command()
@add_secret_scan_common_options()
@click.pass_context
@exception_wrapper
def changes_cmd(ctx: click.Context, **kwargs: Any) -> int:
    """
    Scan the set of changes between the default branch and the current HEAD, including staged changes.
    """
    ctx_obj = ContextObj.get(ctx)
    ctx_obj.client = create_client_from_config(ctx_obj.config)
    config = ctx_obj.config
    check_git_dir()

    default_branch = get_default_branch()
    commit_list = get_list_commit_SHA(f"{default_branch}..HEAD")

    ui.display_verbose(
        f"Scan staged changes and {len(commit_list)} new {pluralize('commit', len(commit_list))}"
    )

    scan_context = ScanContext(
        scan_mode=ScanMode.CHANGE,
        command_path=ctx.command_path,
        target_path=Path.cwd(),
    )

    return scan_commit_range(
        client=ctx_obj.client,
        cache=ctx_obj.cache,
        commit_list=commit_list,
        output_handler=create_output_handler(ctx),
        exclusion_regexes=ctx_obj.exclusion_regexes,
        secret_config=config.user_config.secret,
        scan_context=scan_context,
    )
