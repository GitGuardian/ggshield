#!/usr/bin/python3
import json
from typing import Any

import click
from pygitguardian.models import HealthCheckResponse

from ggshield.cmd.utils.common_options import (
    add_common_options,
    instance_option,
    json_option,
    text_json_format_option,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.client import create_client_from_config
from ggshield.core.errors import UnexpectedError
from ggshield.core.text_utils import STYLE, format_text


@click.command()
@text_json_format_option
@json_option
@instance_option
@add_common_options()
@click.pass_context
def status_cmd(ctx: click.Context, **kwargs: Any) -> int:
    """Show API status and version, along with API key and instance sources."""
    ctx_obj = ContextObj.get(ctx)
    client = create_client_from_config(ctx_obj.config)
    response: HealthCheckResponse = client.health_check()

    if not isinstance(response, HealthCheckResponse):
        raise UnexpectedError("Unexpected health check response")

    instance, instance_source = ctx_obj.config.get_instance_name_and_source()
    _, api_key_source = ctx_obj.config.get_api_key_and_source()
    if ctx_obj.use_json:
        json_output = response.to_dict()
        json_output["instance"] = instance
        json_output["instance_source"] = instance_source.name
        json_output["api_key_source"] = api_key_source.name
        click.echo(json.dumps(json_output))
    else:
        click.echo(
            f"{format_text('API URL:', STYLE['key'])} {instance}\n"
            f"{format_text('Status:', STYLE['key'])} {format_healthcheck_status(response)}\n"
            f"{format_text('App version:', STYLE['key'])} {response.app_version or 'Unknown'}\n"
            f"{format_text('Secrets engine version:', STYLE['key'])} "
            f"{response.secrets_engine_version or 'Unknown'}\n\n"
            f"{format_text('Instance source:', STYLE['key'])} {instance_source.value}\n"
            f"{format_text('API key source:', STYLE['key'])} {api_key_source.value}\n"
        )

    return 0


def format_healthcheck_status(health_check: HealthCheckResponse) -> str:
    (color, status) = (
        ("red", f"unhealthy ({health_check.detail})")
        if health_check.status_code != 200
        else ("green", "healthy")
    )

    return format_text(status, {"fg": color})
