#!/usr/bin/python3
from typing import Any

import click
from pygitguardian import GGClient
from pygitguardian.models import HealthCheckResponse

from ggshield.cmd.common_options import add_common_options
from ggshield.core.client import create_client_from_config
from ggshield.core.errors import UnexpectedError
from ggshield.core.text_utils import STYLE, format_text
from ggshield.core.utils import json_output_option_decorator
from ggshield.output.text.message import format_healthcheck_status


@click.command()
@add_common_options()
@click.pass_context
def status_cmd(ctx: click.Context, json_output: bool, **kwargs: Any) -> int:
    """Show API status."""
    client: GGClient = create_client_from_config(ctx.obj["config"])
    response: HealthCheckResponse = client.health_check()

    if not isinstance(response, HealthCheckResponse):
        raise UnexpectedError("Unexpected health check response")

    click.echo(
        response.to_json()
        if json_output
        else (
            f"{format_text('API URL:', STYLE['key'])} {client.base_uri}\n"
            f"{format_text('Status:', STYLE['key'])} {format_healthcheck_status(response)}\n"
            f"{format_text('App version:', STYLE['key'])} {response.app_version or 'Unknown'}\n"
            f"{format_text('Secrets engine version:', STYLE['key'])} "
            f"{response.secrets_engine_version or 'Unknown'}\n"
        )
    )

    return 0


status = json_output_option_decorator(status_cmd)
