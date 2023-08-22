from typing import Any

import click

from ggshield.cmd.secret.ignore import ignore_cmd
from ggshield.cmd.secret.scan import scan_group
from ggshield.cmd.utils.common_options import add_common_options


@click.group(commands={"scan": scan_group, "ignore": ignore_cmd})
@add_common_options()
def secret_group(**kwargs: Any) -> None:
    """Commands to work with secrets."""
