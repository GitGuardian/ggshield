from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.lazy_group import PluginAwareLazyGroup


@click.group(
    cls=PluginAwareLazyGroup,
    plugin_scope="machine",
    lazy_commands={
        "setup": "ggshield.cmd.machine.setup:setup_cmd",
        "doctor": "ggshield.cmd.machine.doctor:doctor_cmd",
    },
)
@add_common_options()
def machine_group(**kwargs: Any) -> None:
    """
    Scan and protect this machine.

    `setup` sets up all of this machine's protections (AI hooks, git hooks, and a
    honeytoken) in one idempotent command. `doctor` checks that everything is
    correctly set up — AI hooks, git hooks, the token's scopes, and the
    `machine_scan` plugin when installed — without changing anything. Secret and
    endpoint scanning (`scan`) is provided by the `machine_scan` plugin and merges
    into this group when it is installed.
    """
