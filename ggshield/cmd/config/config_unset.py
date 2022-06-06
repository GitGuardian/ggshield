from typing import Optional

import click

from ggshield.core.config import Config

from .constants import FIELD_OPTIONS


@click.command()
@click.argument("field_name", nargs=1, type=click.Choice(FIELD_OPTIONS), required=True)
@click.option(
    "--instance",
    "instance_url",
    required=False,
    type=str,
    metavar="URL",
    help="Set per instance configuration.",
)
@click.option("--all", "all_", is_flag=True, help="Iterate over every instances.")
@click.pass_context
def config_unset_command(
    ctx: click.Context, field_name: str, instance_url: Optional[str], all_: bool
) -> int:
    """
    Remove the value of the given configuration key.
    If --all is passed, it iterates over all instances.
    """
    config: Config = ctx.obj["config"]

    if all_:
        setattr(config.auth_config, field_name, None)
        for instance in config.auth_config.instances:
            setattr(instance, field_name, None)

    elif instance_url is None:
        setattr(config.auth_config, field_name, None)

    else:
        instance = config.auth_config.get_instance(instance_url)
        setattr(instance, field_name, None)

    config.auth_config.save()
    return 0
