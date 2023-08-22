from typing import Any

import click

from ggshield.cmd.honeytoken.create import create_cmd
from ggshield.cmd.utils.common_options import add_common_options


@click.group(commands={"create": create_cmd})
@add_common_options()
def honeytoken_group(**kwargs: Any) -> None:
    """Commands to work with honeytokens."""
