#!/usr/bin/python3
from typing import Any

import click
from pygitguardian.models import HealthCheckResponse

from ggshield.cmd.utils.common_options import add_common_options, json_option
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.client import create_client_from_config
from ggshield.core.errors import UnexpectedError
from ggshield.core.text_utils import STYLE, format_text


@click.command()
@json_option
@add_common_options()
@click.pass_context
def status_cmd(ctx: click.Context, **kwargs: Any) -> int:
    """Show API status and version."""
    ctx_obj = ContextObj.get(ctx)
    client = create_client_from_config(ctx_obj.config, ctx_obj.ui)
    response: HealthCheckResponse = client.health_check()

    if not isinstance(response, HealthCheckResponse):
        raise UnexpectedError("Unexpected health check response")

    click.echo(
        response.to_json()
        if ctx_obj.use_json
        else (
            f"{format_text('API URL:', STYLE['key'])} {client.base_uri}\n"
            f"{format_text('Status:', STYLE['key'])} {format_healthcheck_status(response)}\n"
            f"{format_text('App version:', STYLE['key'])} {response.app_version or 'Unknown'}\n"
            f"{format_text('Secrets engine version:', STYLE['key'])} "
            f"{response.secrets_engine_version or 'Unknown'}\n"
        )
    )

    return 0


def format_healthcheck_status(health_check: HealthCheckResponse) -> str:
    (color, status) = (
        ("red", f"unhealthy ({health_check.detail})")
        if health_check.status_code != 200
        else ("green", "healthy")
    )

    return format_text(status, {"fg": color})
