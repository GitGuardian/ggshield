#!/usr/bin/python3
from typing import Any, Union

import click
from pygitguardian import GGClient
from pygitguardian.models import Detail, Quota, QuotaResponse

from ggshield.cmd.utils.common_options import (
    add_common_options,
    instance_option,
    json_option,
    text_json_format_option,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.quota import format_quota_color
from ggshield.core.client import create_client_from_config
from ggshield.core.errors import UnexpectedError


@click.command()
@text_json_format_option
@json_option
@instance_option
@add_common_options()
@click.pass_context
def quota_cmd(ctx: click.Context, **kwargs: Any) -> int:
    """
    Show the remaining quota of API calls available for the entire workspace.
    """
    ctx_obj = ContextObj.get(ctx)
    client: GGClient = create_client_from_config(ctx_obj.config)
    response: Union[Detail, QuotaResponse] = client.quota_overview()

    if not isinstance(response, (Detail, QuotaResponse)):
        raise UnexpectedError("Unexpected quota response")

    if isinstance(response, Detail):
        raise UnexpectedError(response.detail)

    quota: Quota = response.content

    click.echo(
        quota.to_json()
        if ctx_obj.use_json
        else (
            f"Quota available: {format_quota_color(quota.remaining, quota.limit)}\n"
            f"Quota used in the last 30 days: {quota.count}\n"
            f"Total Quota of the workspace: {quota.limit}\n"
        )
    )

    return 0
