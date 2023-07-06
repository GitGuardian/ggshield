import logging
from typing import Any

import click

from ggshield.cmd.common_options import add_common_options
from ggshield.core.config import Config
from ggshield.core.text_utils import STYLE, format_text
from ggshield.hmsl import get_client


logger = logging.getLogger(__name__)


@click.command()
@click.pass_context
@add_common_options()
def status_cmd(
    ctx: click.Context,
    **kwargs: Any,
) -> int:
    """
    Make sure the HasMySecretLeaked service is working properly.
    """

    # Get our client
    config: Config = ctx.obj["config"]
    client = get_client(config)

    click.echo(
        f"{format_text('API URL:', STYLE['key'])} {client.url}\n"
        f"{format_text('Authenticated:', STYLE['key'])} {str(client.jwt is not None).lower()}\n"
        f"{format_text('Status:', STYLE['key'])} {format_status(client.status)}\n"
    )

    return 0


def format_status(health_check: bool) -> str:
    (color, status) = ("green", "healthy") if health_check else ("red", "unhealthy")
    return format_text(status, {"fg": color})
