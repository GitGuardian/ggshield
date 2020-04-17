#!/usr/bin/python3
import os

import click

from .cli.install import install
from .cli.scan import scan
from .pygitguardian import GGClient
from .config import load_config

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.pass_context
def cli(ctx: object):
    token = os.getenv("GITGUARDIAN_API_KEY")
    base_uri = os.getenv("GITGUARDIAN_API_URL")
    if not token:
        raise click.ClickException("GitGuardian Token is needed.")

    ctx.ensure_object(dict)
    ctx.obj["client"] = GGClient(token=token, base_uri=base_uri)
    ctx.obj["config"] = load_config()


cli.add_command(scan)
cli.add_command(install)

if __name__ == "__main__":
    cli()
