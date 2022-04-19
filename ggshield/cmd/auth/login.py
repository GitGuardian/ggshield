import click

from ggshield.cmd.auth.utils import check_instance_has_enabled_flow
from ggshield.core.client import retrieve_client
from ggshield.core.config import AccountConfig, InstanceConfig
from ggshield.core.oauth import OAuthClient
from ggshield.core.utils import clean_url


@click.command()
@click.option(
    "--method",
    required=True,
    type=click.Choice(["token", "web"]),
    help="Authentication method.",
)
@click.option(
    "--instance",
    required=False,
    type=str,
    help="URL of the instance to authenticate to.",
)
@click.option(
    "--token-name",
    required=False,
    type=str,
    help="Name of new token.",
)
@click.pass_context
def login_cmd(ctx: click.Context, method: str, instance: str, token_name: str) -> int:
    """
    Authenticate to your GitGuardian account.

    Use `--method token` to authenticate using an existing token.

    Use `--method web` to let ggshield authenticate through your web browser and
    generate a token for you. Note: This is experimental for now.
    """
    config = ctx.obj["config"]

    if instance:
        parsed_url = clean_url(instance)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise click.BadParameter(
                "Please provide a valid URL.",
                param_hint="instance",
            )
        instance = f"{parsed_url.scheme}://{parsed_url.netloc}"

    if not instance:
        instance = config.auth_config.default_instance

    config.auth_config.current_instance = instance
    instance_config = config.auth_config.instances.setdefault(
        instance,
        InstanceConfig(
            # account is initialized as None because the instance must exist in
            # the config before using the client
            account=None,  # type: ignore
            url=instance,
        ),
    )

    if method == "token":
        token = click.prompt("Enter your GitGuardian API token", hide_input=True)
        if not token:
            raise click.ClickException("No API token was provided.")

        config.auth_config.current_token = token

        client = retrieve_client(config)
        response = client.get(endpoint="token")
        if not response.ok:
            raise click.ClickException("Authentication failed with token.")

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
        return 0

    check_instance_has_enabled_flow(config=config)

    if method == "web":
        OAuthClient(config, instance).oauth_process(token_name=token_name)
    return 0
