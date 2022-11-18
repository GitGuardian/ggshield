from typing import Any

import click

from ggshield.cmd.common_options import add_common_options
from ggshield.cmd.iac.scan import scan_cmd


@click.group(commands={"scan": scan_cmd})
@add_common_options()
def iac_group(**kwargs: Any) -> None:
    """Commands to work with infrastructure as code."""
