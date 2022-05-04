import click

from .login import login_cmd
from .logout import logout_cmd


@click.group(commands={"login": login_cmd, "logout": logout_cmd})
def auth_group() -> None:
    """Commands to manage authentication."""
