from typing import Any

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
)


@click.command()
@click.option(
    "--mode",
    type=click.Choice(["cursor"]),
    required=True,
    help="The AI tool mode to use.",
)
@add_secret_scan_common_options()
@click.pass_context
def ai_hook_cmd(
    ctx: click.Context,
    mode: str,
    **kwargs: Any,
) -> int:
    """
    Scan AI tool interactions for secrets.
    """
    return 0
