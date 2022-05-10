from typing import Optional

import click

from ggshield.core.config import Config, UnknownInstanceError

from .constants import FIELD_OPTIONS


@click.command()
@click.argument("field_name", nargs=1, type=click.Choice(FIELD_OPTIONS), required=True)
@click.option(
    "--instance",
    "instance_url",
    required=False,
    type=str,
    metavar="URL",
    help="URL of the instance to get the config.",
)
@click.pass_context
def config_get_command(
    ctx: click.Context, field_name: str, instance_url: Optional[str]
) -> int:
    """
    Get the value of the specified parameter.
    If --instance is passed, retrieve the value for this specific instance
    """
    config: Config = ctx.obj["config"]

    if instance_url is None:
        value = getattr(config.auth_config, field_name, None)
        if value is None:
            try:
                instance_config = config.auth_config.get_instance(config.instance_name)
            except UnknownInstanceError:
                pass
            else:
                value = getattr(instance_config, field_name, None)
    else:
        instance_config = config.auth_config.get_instance(instance_url)
        value = getattr(instance_config, field_name, None)

    if value is None:
        value = "not set"
    click.echo(f"{field_name}: {value}")
    return 0
