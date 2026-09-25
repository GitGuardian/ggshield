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
        # Answered by the native executable; these are stubs for --help.
        "get": "ggshield.cmd.secret.store:get_cmd",
        "set": "ggshield.cmd.secret.store:set_cmd",
        "unset": "ggshield.cmd.secret.store:unset_cmd",
        "list": "ggshield.cmd.secret.store:list_cmd",
        "import": "ggshield.cmd.secret.store:import_cmd",
        "encrypt": "ggshield.cmd.secret.store:encrypt_cmd",
    },
)
@add_common_options()
def secret_group(**kwargs: Any) -> None:
    """Commands to work with secrets."""
