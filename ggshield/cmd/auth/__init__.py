from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options

from .login import login_cmd
from .logout import logout_cmd


@click.group(commands={"login": login_cmd, "logout": logout_cmd})
@add_common_options()
def auth_group(**kwargs: Any) -> None:
    """Commands to manage authentication."""
