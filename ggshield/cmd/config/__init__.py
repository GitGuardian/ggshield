import click

from .config_list import config_list_cmd
from .config_set import config_set_command


@click.group(
    commands={
        "list": config_list_cmd,
        "set": config_set_command,
    }
)
def config_group() -> None:
    """Commands to manage auth config."""
