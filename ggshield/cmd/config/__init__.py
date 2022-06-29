import click

from .config_get import config_get_command
from .config_list import config_list_cmd
from .config_migrate import config_migrate_cmd
from .config_set import config_set_command
from .config_unset import config_unset_command


@click.group(
    commands={
        "list": config_list_cmd,
        "set": config_set_command,
        "unset": config_unset_command,
        "get": config_get_command,
        "migrate": config_migrate_cmd,
    }
)
def config_group() -> None:
    """Commands to manage configuration."""
