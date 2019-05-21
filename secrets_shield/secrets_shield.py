#!/usr/bin/python3


import click
from secrets_shield.cli.scan import scan
from secrets_shield.cli.install import install

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option(
    "--token", envvar="GG_SCANNING_API_TOKEN", help="GG Public Scanning Token"
)
def cli(token):
    pass


cli.add_command(scan)
cli.add_command(install)

if __name__ == "__main__":
    cli()
