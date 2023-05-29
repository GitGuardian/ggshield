from typing import Any

import click

from ggshield.cmd.common_options import add_common_options
from ggshield.cmd.iac.precommit import precommit_cmd
from ggshield.cmd.iac.scan import scan_cmd
from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
)


@click.group(commands={"scan": scan_cmd, "pre-commit": precommit_cmd})
@add_secret_scan_common_options()
@add_common_options()
def iac_group(**kwargs: Any) -> None:
    """Commands to work with infrastructure as code."""
