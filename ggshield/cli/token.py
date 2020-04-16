import sys
import click

from functools import wraps
from typing import Dict, List

from ggshield.client import PublicScanningException

CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


def catch_public_scanning(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except PublicScanningException as err:
            click.echo("{} : {}".format(click.style("Error", fg="red"), str(err)))
            sys.exit(1)

    return decorator


@click.group(context_settings=CONTEXT_SETTINGS)
@click.pass_context
def token(ctx: object) -> int:
    """ Command to manage Gitguardian token. """
    pass


@token.command()
@click.argument("token_id", nargs=1, type=click.STRING, required=True)
@click.pass_context
@catch_public_scanning
def show(ctx: object, token_id: str):
    """ Show token information. """
    token = ctx.obj["client"].retrieve_token(token_id)
    click.echo(display_token(token))


@token.command()
@click.pass_context
@catch_public_scanning
def list(ctx: object) -> int:
    """ List all tokens. """
    for token in ctx.obj["client"].list_tokens():
        click.echo(display_token(token))


@token.command()
@click.option("--namespace", help="Display status for the given namespace.")
@click.pass_context
@catch_public_scanning
def status(ctx: object, namespace: str):
    """ Get quotas status. """

    status = ctx.obj["client"].quotas()

    if namespace and status.get(namespace):
        click.echo(display_status(namespace, status[namespace]))

    else:
        for namespace, quotas in status.items():
            click.echo(display_status(namespace, quotas))


@token.command()
@click.argument("name", nargs=1, type=click.STRING, required=False)
@click.pass_context
@catch_public_scanning
def create(ctx: object, name: str):
    """ Create a new token. """
    token = ctx.obj["client"].create_token(name or "")
    click.echo(display_token(token))


@token.command()
@click.argument("token_id", nargs=1, type=click.STRING, required=True)
@click.pass_context
@catch_public_scanning
def delete(ctx: object, token_id: List):
    """ Delete a token. """
    click.echo(ctx.obj["client"].delete_token(token_id)["detail"])


def display_token(token: Dict) -> str:
    """ Format the token data into a readable string """
    display = {"name": "Name", "id": "ID", "key": "Key", "createdAt": "Created"}
    message = ""

    for key, value in token.items():
        message += "{}\t: {}\n".format(display[key], value)

    return message


def display_status(namespace: str, quotas: Dict) -> str:
    """ Return quotas status information. """
    return "Namespace\t: {}\nCalls\t\t: {}\nLimit\t\t: {}\nInterval\t: {}\n".format(
        namespace, quotas["calls_count"], quotas["limit"], quotas["interval"]
    )
