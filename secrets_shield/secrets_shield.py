#!/usr/bin/python3


import click
from secrets_shield.cli.scan import scan
from secrets_shield.cli.install import install

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option("--token", envvar="GITGUARDIAN_TOKEN", help="GitGuardian Token.")
@click.pass_context
def cli(ctx, token):
    if not token:
        raise click.ClickException(f"GitGuardian Token is needed.")

    ctx.ensure_object(dict)
    ctx.obj["token"] = token


cli.add_command(scan)
cli.add_command(install)

if __name__ == "__main__":
    cli()
