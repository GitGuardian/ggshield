from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options

from .install import install_cmd
from .uninstall import uninstall_cmd
from .update import update_cmd


@click.group(
    commands={"install": install_cmd, "update": update_cmd, "uninstall": uninstall_cmd}
)
@add_common_options()
def skill_group(**kwargs: Any) -> None:
    """Manage the ggshield AI assistant skill."""
