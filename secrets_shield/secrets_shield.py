#!/usr/bin/python3


import click

from typing import List

from secrets_shield.cli.scan import scan
from secrets_shield.cli.install import install
from secrets_shield.cli.token import token

from secrets_shield.client import PublicScanningApiClient
from secrets_shield.config import load_config

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("--token", envvar="GITGUARDIAN_TOKEN", help="GitGuardian Token.")
@click.option("--blacklist", "-b", multiple=True, help="Extend blacklist of detectors.")
@click.option("--set-blacklist", "-B", multiple=True, help="Set detectors blacklist.")
@click.pass_context
def cli(ctx: object, token: str, blacklist: List, set_blacklist: List):
    if not token:
        raise click.ClickException(f"GitGuardian Token is needed.")

    ctx.ensure_object(dict)
    ctx.obj["client"] = PublicScanningApiClient(token)
    ctx.obj["config"] = load_config()

    if set_blacklist:
        ctx.obj["config"]["blacklist"] = set_blacklist

    elif blacklist:
        ctx.obj["config"]["blacklist"].update(blacklist)


cli.add_command(scan)
cli.add_command(install)
cli.add_command(token)

if __name__ == "__main__":
    cli()
