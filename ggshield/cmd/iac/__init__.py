from typing import Any

import click

from ggshield.cmd.iac.scan import iac_scan_group
from ggshield.cmd.utils.common_options import add_common_options


@click.group(commands={"scan": iac_scan_group})
@add_common_options()
def iac_group(**kwargs: Any) -> None:
    """Commands to work with Infra as Code."""
