import click

from ggshield.cmd.iac.scan import scan_cmd


@click.group(commands={"scan": scan_cmd})
def iac_group() -> None:
    """Commands to work with infrastructure as code."""
