#!/usr/bin/python3

import click

from .cli.scan import scan
from .cli.token import token
from .cli.install import install

from .config import load_config
from .client import PublicScanningApiClient

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("--token", envvar="GITGUARDIAN_TOKEN", help="GitGuardian Token.")
@click.pass_context
def cli(ctx: object, token: str):
    if not token:
        raise click.ClickException("GitGuardian Token is needed.")

    ctx.ensure_object(dict)
    ctx.obj["client"] = PublicScanningApiClient(token)
    ctx.obj["config"] = load_config()


cli.add_command(scan)
cli.add_command(install)
cli.add_command(token)

if __name__ == "__main__":
    cli()
