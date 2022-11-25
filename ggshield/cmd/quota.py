#!/usr/bin/python3
from typing import Any, Union

import click
from pygitguardian import GGClient
from pygitguardian.models import Detail, Quota, QuotaResponse

from ggshield.cmd.common_options import add_common_options
from ggshield.core.client import create_client_from_config
from ggshield.core.errors import UnexpectedError
from ggshield.core.utils import json_output_option_decorator
from ggshield.output.text.message import format_quota_color


@click.command()
@json_output_option_decorator
@add_common_options()
@click.pass_context
def quota_cmd(ctx: click.Context, json_output: bool, **kwargs: Any) -> int:
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
        if json_output
        else (
            f"Quota available: {format_quota_color(quota.remaining, quota.limit)}\n"
            f"Quota used in the last 30 days: {quota.count}\n"
            f"Total Quota of the workspace: {quota.limit}\n"
        )
    )

    return 0
