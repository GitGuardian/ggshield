import logging
from typing import Any

import click

from ggshield.cmd.common_options import add_common_options
from ggshield.cmd.quota import format_quota_color
from ggshield.core.config import Config
from ggshield.hmsl import get_client


logger = logging.getLogger(__name__)


@click.command()
@click.pass_context
@add_common_options()
def quota_cmd(
    ctx: click.Context,
    **kwargs: Any,
) -> int:
    """
    Get the number of remaining credits for today.
    """

    # Get our client
    config: Config = ctx.obj["config"]
    client = get_client(config)

    click.echo(
        f"Quota limit: {client.quota.limit}\n"
        f"Quota available: {format_quota_color(client.quota.remaining, client.quota.limit)}\n"
        f"Quota reset: {client.quota.reset.isoformat()}\n"
    )

    return 0
