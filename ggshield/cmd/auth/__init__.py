from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options

from .login import login_cmd
from .logout import logout_cmd


# Note: `ggshield auth status` is an alias of the top-level `api-status`
# command. The alias is wired in ggshield.__main__ (the composition root)
# rather than here, because ggshield.cmd.auth must not import
# ggshield.cmd.status (cmd.* siblings are kept independent, see .importlinter).
@click.group(
    commands={
        "login": login_cmd,
        "logout": logout_cmd,
    }
)
@add_common_options()
def auth_group(**kwargs: Any) -> None:
    """Commands to manage authentication."""
