#!/usr/bin/python3
from typing import Any, Union

import click
from pygitguardian import GGClient
from pygitguardian.models import Detail, Quota, QuotaResponse

from ggshield.cmd.common_options import add_common_options, json_option, use_json
from ggshield.core.client import create_client_from_config
from ggshield.core.errors import UnexpectedError
from ggshield.core.text_utils import format_text


@click.command()
@json_option
@add_common_options()
@click.pass_context
def quota_cmd(ctx: click.Context, **kwargs: Any) -> int:
    """Show quotas overview."""
    client: GGClient = create_client_from_config(ctx.obj["config"])
    response: Union[Detail, QuotaResponse] = client.quota_overview()

    if not isinstance(response, (Detail, QuotaResponse)):
        raise UnexpectedError("Unexpected quota response")

    if isinstance(response, Detail):
        raise UnexpectedError(response.detail)

    quota: Quota = response.content

    click.echo(
        quota.to_json()
        if use_json(ctx)
        else (
            f"Quota available: {format_quota_color(quota.remaining, quota.limit)}\n"
            f"Quota used in the last 30 days: {quota.count}\n"
            f"Total Quota of the workspace: {quota.limit}\n"
        )
    )

    return 0


def format_quota_color(remaining: int, limit: int) -> str:
    if limit == 0:
        return format_text(str(remaining), {"fg": "white"})

    available_percent = remaining / limit
    if available_percent < 0.25:
        color = "red"
    elif available_percent < 0.75:
        color = "yellow"
    else:
        color = "green"

    return format_text(str(remaining), {"fg": color})
