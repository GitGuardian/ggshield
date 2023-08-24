from typing import Any

import click

from ggshield.cmd.utils.common_options import add_common_options

from .scan import scan_group


@click.group(commands={"scan": scan_group})
@add_common_options()
def sca_group(**kwargs: Any) -> None:
    """Commands to work with SCA."""
