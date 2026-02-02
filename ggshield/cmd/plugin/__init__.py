"""
Plugin commands for managing ggshield plugins.
"""

from typing import Any

import click

from ggshield.cmd.plugin.install import install_cmd
from ggshield.cmd.plugin.manage import disable_cmd, enable_cmd, uninstall_cmd
from ggshield.cmd.plugin.plugin_list import list_cmd
from ggshield.cmd.plugin.status import status_cmd
from ggshield.cmd.plugin.update import update_cmd
from ggshield.cmd.utils.common_options import add_common_options


@click.group(
    commands={
        "install": install_cmd,
        "list": list_cmd,
        "status": status_cmd,
        "enable": enable_cmd,
        "disable": disable_cmd,
        "uninstall": uninstall_cmd,
        "update": update_cmd,
    }
)
@add_common_options()
def plugin_group(**kwargs: Any) -> None:
    """
    Manage ggshield plugins.

    Plugins extend ggshield with additional capabilities like local secret
    detection. Use 'ggshield plugin status' to see available plugins
    for your GitGuardian account.

    Examples:

        # Check available plugins for your account
        ggshield plugin status

        # Install a plugin
        ggshield plugin install tokenscanner

        # List installed plugins
        ggshield plugin list

        # Check for updates
        ggshield plugin update --check
    """
    pass
