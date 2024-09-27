from typing import Any

import click

from ggshield.cmd.iac.scan.all import scan_all_cmd
from ggshield.cmd.iac.scan.ci import scan_ci_cmd
from ggshield.cmd.iac.scan.diff import scan_diff_cmd
from ggshield.cmd.iac.scan.iac_scan_common_options import add_iac_scan_common_options
from ggshield.cmd.iac.scan.precommit import scan_pre_commit_cmd
from ggshield.cmd.iac.scan.prepush import scan_pre_push_cmd
from ggshield.cmd.iac.scan.prereceive import scan_pre_receive_cmd
from ggshield.cmd.utils.common_options import directory_argument
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.utils.click import DefaultCommandGroup


@click.group(
    cls=DefaultCommandGroup,
    commands={
        "all": scan_all_cmd,
        "ci": scan_ci_cmd,
        "diff": scan_diff_cmd,
        "pre-commit": scan_pre_commit_cmd,
        "pre-push": scan_pre_push_cmd,
        "pre-receive": scan_pre_receive_cmd,
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
# Changes to arguments must be propagated to scan_all_cmd
@iac_scan_group.command(default_command=True)
@add_iac_scan_common_options()
@directory_argument
@click.pass_context
def default_command(ctx: click.Context, **kwargs: Any) -> int:
    """Deprecated. Use `ggshield iac scan all` instead"""
    ui.display_warning("Deprecated. Please use 'ggshield iac scan all' instead")
    result: int = scan_all_cmd.invoke(ctx)
    return result


def scan_group_impl(ctx: click.Context) -> int:
    """Implementation for scan_group(). Must be a separate function so that its code can
    be reused from the deprecated `cmd.scan` package."""
    if ctx.invoked_subcommand is None:
        scan_all_cmd.invoke(ctx)

    ctx_obj = ContextObj.get(ctx)
    ctx_obj.client = create_client_from_config(ctx_obj.config)

    return 0
