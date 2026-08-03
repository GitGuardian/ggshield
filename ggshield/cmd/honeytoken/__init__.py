from typing import Any

import click

from ggshield.cmd.honeytoken.create import create_cmd
from ggshield.cmd.honeytoken.create_with_context import create_with_context_cmd
from ggshield.cmd.honeytoken.plant import plant_cmd
from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.lazy_group import PluginAwareLazyGroup


@click.group(
    cls=PluginAwareLazyGroup,
    plugin_scope="honeytoken",
    commands={
        "create": create_cmd,
        "create-with-context": create_with_context_cmd,
        "plant": plant_cmd,
    },
)
@add_common_options()
def honeytoken_group(**kwargs: Any) -> None:
    """Commands to work with honeytokens."""
