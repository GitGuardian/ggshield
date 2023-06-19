from typing import Any

import click

from ggshield.cmd.common_options import add_common_options

from .scan import scan_diff_cmd, scan_full_cmd


@click.group(commands={"scan_diff": scan_diff_cmd, "scan_full": scan_full_cmd})
@add_common_options()
def sca_group(**kwargs: Any) -> None:
    """Commands to work with SCA."""
