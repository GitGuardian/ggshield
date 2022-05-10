import click

from .config_list import config_list_cmd


@click.group(
    commands={
        "list": config_list_cmd,
    }
)
def config_group() -> None:
    """Commands to manage auth config."""
