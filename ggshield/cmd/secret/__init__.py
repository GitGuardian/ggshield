from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.lazy_group import PluginAwareLazyGroup


@click.group(
    cls=PluginAwareLazyGroup,
    plugin_scope="secret",
    lazy_commands={
        "scan": "ggshield.cmd.secret.scan:scan_group",
        "ignore": "ggshield.cmd.secret.ignore:ignore_cmd",
    },
)
@add_common_options()
def secret_group(**kwargs: Any) -> None:
    """Commands to work with secrets."""
