import os
from typing import Any, Optional

import click

from ggshield.cmd.iac.scan.diff import scan_diff_cmd
from ggshield.cmd.iac.scan.iac_scan_common_options import (
    add_iac_scan_common_options,
    directory_argument,
)
from ggshield.cmd.iac.scan.scan import scan_all_cmd
from ggshield.core.clickutils.default_command_group import DefaultCommandGroup
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.text_utils import display_error, display_warning


@click.group(
    cls=DefaultCommandGroup,
    commands={
        "all": scan_all_cmd,
        "diff": scan_diff_cmd,
    },
    invoke_without_command=True,
)
@add_iac_scan_common_options()
@click.pass_context
def iac_scan_group(
    ctx: click.Context,
    **kwargs: Any,
) -> int:
    """Commands to scan various contents."""
    return scan_group_impl(ctx)


# Alias to "ggshield iac scan all"
# Kept for compatibility
@iac_scan_group.command(default_command=True)
@add_iac_scan_common_options()
@directory_argument
@click.pass_context
def default_command(ctx: click.Context, **kwargs: Any) -> int:
    """Deprecated. Use `ggshield iac scan all` instead"""
    display_warning("Deprecated. Please use 'ggshield iac scan all' instead")
    result: int = scan_all_cmd.invoke(ctx)
    return result


def scan_group_impl(ctx: click.Context) -> int:
    """Implementation for scan_group(). Must be a separate function so that its code can
    be reused from the deprecated `cmd.scan` package."""
    if ctx.invoked_subcommand is None:
        scan_all_cmd.invoke(ctx)

    ctx.obj["client"] = create_client_from_config(ctx.obj["config"])
    return_code = 0

    config: Config = ctx.obj["config"]

    max_commits = get_max_commits_for_hook()
    if max_commits:
        config.max_commits_for_hook = max_commits

    return return_code


def get_max_commits_for_hook() -> Optional[int]:
    """
    Get the maximum number of commits that should be processed for a hook.
    """
    try:
        max_commits = os.getenv("GITGUARDIAN_MAX_COMMITS_FOR_HOOK", None)
        if max_commits is not None:
            return int(max_commits)
    except BaseException as e:
        display_error(f"Unable to parse GITGUARDIAN_MAX_COMMITS_FOR_HOOK: {str(e)}")
        return None

    return None
