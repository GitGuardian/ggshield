import click

from .client import retrieve_client


@click.command()
@click.option(
    "--method",
    required=True,
    type=click.Choice(["token"]),
    help="Authentication method.",
)
@click.pass_context
def login_cmd(ctx: click.Context, method: str) -> int:
    """Authenticate to your GitGuardian account."""
    if method == "token":
        token = click.prompt("Enter your GitGuardian API token", hide_input=True)
        if not token:
            raise click.ClickException("No API token was provided.")

        config = ctx.obj["config"]
        config.auth_config.current_token = token

        client = retrieve_client(config)
        response = client.get(endpoint="token")
        if response.ok:
            pass
        else:
            raise click.ClickException("Authentication failed with token.")
    return 0


@click.group(commands={"login": login_cmd})
def auth() -> None:
    """Command to manage authentication."""
