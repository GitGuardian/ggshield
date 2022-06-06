from typing import Optional

import click

from ggshield.core.config import Config

from .constants import FIELD_OPTIONS


@click.command()
@click.argument("field_name", nargs=1, type=click.Choice(FIELD_OPTIONS), required=True)
@click.argument("value", nargs=1, type=click.STRING, required=True)
@click.option(
    "--instance",
    required=False,
    type=str,
    metavar="URL",
    help="Set per instance configuration.",
)
@click.pass_context
def config_set_command(
    ctx: click.Context, field_name: str, value: str, instance: Optional[str]
) -> int:
    """
    Update the value of the given configuration key.
    """
    config: Config = ctx.obj["config"]

    # value type checking must be done per case
    if field_name == "default_token_lifetime":
        try:
            value = int(value)  # type: ignore
        except ValueError:
            raise click.ClickException("default_token_lifetime must be an int")

    if instance is None:
        setattr(config.auth_config, field_name, value)

    else:
        instance_config = config.auth_config.get_instance(instance)
        setattr(instance_config, field_name, value)

    config.auth_config.save()
    return 0
