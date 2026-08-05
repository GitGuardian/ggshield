from typing import Any

import click

from ggshield.cmd.ai.discover import discover_cmd
from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.lazy_group import PluginAwareLazyGroup


@click.group(
    cls=PluginAwareLazyGroup,
    plugin_scope="ai",
    commands={"discover": discover_cmd},
)
@add_common_options()
def ai_group(**kwargs: Any) -> None:
    """Commands to work with AI assistants."""
