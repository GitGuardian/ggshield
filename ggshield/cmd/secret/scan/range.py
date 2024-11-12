from pathlib import Path
from typing import Any

import click
from click import UsageError

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.client import create_client_from_config
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.utils.git_shell import get_list_commit_SHA
from ggshield.verticals.secret.repo import scan_commit_range


@click.command()
@click.argument("commit_range", nargs=1, type=click.STRING)
@add_secret_scan_common_options()
@click.pass_context
@exception_wrapper
def range_cmd(
    ctx: click.Context,
    commit_range: str,
    **kwargs: Any,
) -> int:  # pragma: no cover
    """
    Scan each commit in the given commit range.

    Any git compatible commit range can be provided as an input.

    Example: `ggshield secret scan commit-range HEAD~1...`
    """
    ctx_obj = ContextObj.get(ctx)
    ctx_obj.client = create_client_from_config(ctx_obj.config)
    config = ctx_obj.config
    commit_list = get_list_commit_SHA(commit_range)
    if not commit_list:
        raise UsageError("invalid commit range")
    ui.display_verbose(f"Commits to scan: {len(commit_list)}")

    scan_context = ScanContext(
        scan_mode=ScanMode.COMMIT_RANGE,
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
