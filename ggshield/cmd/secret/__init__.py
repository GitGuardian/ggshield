import click

from ggshield.cmd.secret.ignore import ignore_cmd
from ggshield.cmd.secret.scan import scan_group


@click.group(commands={"scan": scan_group, "ignore": ignore_cmd})
def secret_group() -> None:
    """Commands to work with secrets."""
