import click

from ggshield.cmd.secret.scan import scan_group


@click.group(commands={"scan": scan_group})
def secret_group() -> None:
    """Commands to work with secrets."""
