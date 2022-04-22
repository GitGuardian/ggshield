import click

from .login import login_cmd


@click.group(commands={"login": login_cmd})
def auth_group() -> None:
    """Commands to manage authentication."""
