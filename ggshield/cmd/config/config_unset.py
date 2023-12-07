from typing import Any, Optional

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj

from .config_set import set_user_config_field
from .constants import FIELD_NAMES, FIELD_NAMES_DOC, FIELDS


@click.command(
    help=f"""Remove the value of the given configuration key.

If `--all` is passed, iterates over all instances.

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
@click.option(
    "--instance",
    "instance_url",
    required=False,
    type=str,
    metavar="URL",
    help="Set per instance configuration.",
)
@click.option("--all", "all_", is_flag=True, help="Iterate over all instances.")
@add_common_options()
@click.pass_context
def config_unset_cmd(
    ctx: click.Context,
    field_name: str,
    instance_url: Optional[str],
    all_: bool,
    **kwargs: Any,
) -> int:
    config = ContextObj.get(ctx).config
    field = FIELDS[field_name]

    if field.auth_config:
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
    else:
        set_user_config_field(field, None)
    return 0
