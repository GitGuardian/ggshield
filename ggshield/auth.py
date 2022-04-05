from urllib.parse import urlparse

import click

from .client import retrieve_client
from .config import AccountConfig, InstanceConfig


@click.command()
@click.option(
    "--method",
    required=True,
    type=click.Choice(["token"]),
    help="Authentication method.",
)
@click.option(
    "--instance",
    required=False,
    type=str,
    help="URL of the instance to authenticate to.",
)
@click.pass_context
def login_cmd(ctx: click.Context, method: str, instance: str) -> int:
    """Authenticate to your GitGuardian account."""
    config = ctx.obj["config"]

    if instance:
        if not instance.startswith("https://"):
            raise click.BadParameter("Instance must be a valid https URL.")

        # Normalize path by removing the path, if it is set
        parsed_url = urlparse(instance)
        instance = f"https://{parsed_url.netloc}"

    if not instance:
        instance = config.auth_config.default_instance

    if method == "token":
        token = click.prompt("Enter your GitGuardian API token", hide_input=True)
        if not token:
            raise click.ClickException("No API token was provided.")

        config.auth_config.current_instance = instance
        config.auth_config.current_token = token

        instance_config = config.auth_config.instances.setdefault(
            instance,
            InstanceConfig(
                # account is initialized as None because the instance must exist in
                # the config before using the client
                account=None,  # type: ignore
                url=instance,
            ),
        )

        client = retrieve_client(config)
        response = client.get(endpoint="token")
        if response.ok:
            api_token_data = response.json()
            scopes = api_token_data["scope"]
            if "scan" not in scopes:
                raise click.ClickException("This token does not have the scan scope.")

            account_config = AccountConfig(
                account_id=api_token_data.get("account_id"),
                token=token,
                expire_at=api_token_data.get("expire_at"),
                token_name=api_token_data.get("name", ""),
                type=api_token_data.get("type", ""),
            )

            instance_config.account = account_config
            config.save()
            click.echo("Authentication was successful.")
        else:
            raise click.ClickException("Authentication failed with token.")
    return 0


@click.group(commands={"login": login_cmd})
def auth() -> None:
    """Command to manage authentication."""
