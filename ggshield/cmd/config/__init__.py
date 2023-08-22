from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options

from .config_get import config_get_cmd
from .config_list import config_list_cmd
from .config_migrate import config_migrate_cmd
from .config_set import config_set_cmd
from .config_unset import config_unset_cmd


@click.group(
    commands={
        "list": config_list_cmd,
        "set": config_set_cmd,
        "unset": config_unset_cmd,
        "get": config_get_cmd,
        "migrate": config_migrate_cmd,
    }
)
@add_common_options()
def config_group(**kwargs: Any) -> None:
    """Commands to manage configuration."""
