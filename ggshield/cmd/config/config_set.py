from typing import Any, Optional

import click
from click import BadParameter

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.config.user_config import UserConfig
from ggshield.core.config.utils import find_global_config_path

from .constants import FIELD_NAMES, FIELD_NAMES_DOC, FIELDS, ConfigField


def set_user_config_field(field: ConfigField, value: Any) -> None:
    config_path = find_global_config_path(to_write=True)
    user_config, _ = UserConfig.load(config_path)
    setattr(user_config, field.name, value)
    user_config.save(config_path)


@click.command(
    help=f"""Update the value of the given configuration key.

{FIELD_NAMES_DOC}
"""
)
@click.argument(
    "field_name",
    nargs=1,
    type=click.Choice(FIELD_NAMES),
    required=True,
    metavar="KEY",
)
@click.argument("value", nargs=1, type=click.STRING, required=True)
@click.option(
    "--instance",
    required=False,
    type=str,
    metavar="URL",
    help="Set per instance configuration.",
)
@add_common_options()
@click.pass_context
def config_set_cmd(
    ctx: click.Context,
    field_name: str,
    value: str,
    instance: Optional[str],
    **kwargs: Any,
) -> int:
    config = ContextObj.get(ctx).config

    field = FIELDS[field_name]

    # value type checking must be done per case
    if field_name == "default_token_lifetime":
        try:
            value = int(value)  # type: ignore
        except ValueError:
            raise BadParameter("default_token_lifetime must be an int")

    if instance:
        if field.per_instance_ok:
            instance_config = config.auth_config.get_instance(instance)
            setattr(instance_config, field_name, value)
        else:
            raise BadParameter(f"{field_name} cannot be set per instance")
        config.auth_config.save()
    elif field.auth_config:
        setattr(config.auth_config, field.name, value)
        config.auth_config.save()
    else:
        set_user_config_field(field, value)
    return 0
