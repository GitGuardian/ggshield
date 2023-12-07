from typing import Any, Optional

import click

from ggshield.cmd.config.constants import FIELD_NAMES, FIELD_NAMES_DOC, FIELDS
from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.errors import UnknownInstanceError


@click.command(
    help=f"""
Print the value of the given configuration key.
If `--instance` is passed, retrieve the value for this specific instance.

{FIELD_NAMES_DOC}"""
)
@click.argument(
    "field_name",
    nargs=1,
    type=click.Choice(FIELD_NAMES),
    required=True,
    metavar="KEY",
)
@click.option(
    "--instance",
    "instance_url",
    required=False,
    type=str,
    metavar="URL",
    help="Get per instance configuration.",
)
@add_common_options()
@click.pass_context
def config_get_cmd(
    ctx: click.Context, field_name: str, instance_url: Optional[str], **kwargs: Any
) -> int:
    config = ContextObj.get(ctx).config
    field = FIELDS[field_name]

    if field.auth_config:
        if instance_url:
            instance_config = config.auth_config.get_instance(instance_url)
            value = getattr(instance_config, field_name, None)
        else:
            value = getattr(config.auth_config, field_name, None)
            if value is None and field.per_instance_ok:
                # No value, try to get the one from the default instance
                try:
                    instance_config = config.auth_config.get_instance(
                        config.instance_name
                    )
                except UnknownInstanceError:
                    pass
                else:
                    value = getattr(instance_config, field_name, None)
    else:
        value = getattr(config.user_config, field_name, None)

    if value is None:
        value = "not set"
    click.echo(f"{field_name}: {value}")
    return 0
