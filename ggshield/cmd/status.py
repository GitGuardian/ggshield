#!/usr/bin/python3

import click
from pygitguardian import GGClient
from pygitguardian.models import HealthCheckResponse

from ggshield.core.client import create_client_from_config
from ggshield.core.text_utils import STYLE, format_text
from ggshield.core.utils import json_output_option_decorator
from ggshield.output.text.message import format_healthcheck_status


@click.command()
@click.pass_context
def status_cmd(ctx: click.Context, json_output: bool) -> int:
    """Show API status."""
    client: GGClient = create_client_from_config(ctx.obj["config"])
    response: HealthCheckResponse = client.health_check()

    if not isinstance(response, HealthCheckResponse):
        raise click.ClickException("Unexpected health check response")

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
