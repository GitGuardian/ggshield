import re
from typing import Optional, Tuple

import click

from ggshield.cmd.auth.utils import check_instance_has_enabled_flow
from ggshield.core.client import create_client
from ggshield.core.config import AccountConfig, Config
from ggshield.core.oauth import OAuthClient
from ggshield.core.utils import clean_url


def validate_login_path(
    instance: Optional[str], sso_url: Optional[str]
) -> Tuple[Optional[str], Optional[str]]:
    """
    Validate that the SSO URL and the instance refer to the same instance if they are both defined,
    that the SSO URL has a correct format
    and return the couple (instance, login_path) that will be used to redirect to the login page
    """
    if sso_url is None:
        return instance, None
    sso_parsed_url = clean_url(sso_url)
    if (
        not sso_parsed_url.scheme
        or not sso_parsed_url.netloc
        or not re.match(
            r"/auth/sso/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            sso_parsed_url.path,
        )
    ):
        raise click.BadParameter(
            "Please provide a valid SSO URL.",
            param_hint="sso-url",
        )
    sso_instance = f"{sso_parsed_url.scheme}://{sso_parsed_url.netloc}"
    sso_login_path = sso_parsed_url.path

    if instance is None:
        return sso_instance, sso_login_path

    config_parsed_url = clean_url(instance)
    if (
        config_parsed_url.scheme != sso_parsed_url.scheme
        or config_parsed_url.netloc != sso_parsed_url.netloc
    ):
        raise click.ClickException("instance and SSO URL params do not match")
    return instance, sso_login_path


@click.command()
@click.option(
    "--method",
    required=False,
    default="web",
    type=click.Choice(["token", "web"]),
    help="Authentication method.",
)
@click.option(
    "--instance",
    required=False,
    type=str,
    help="URL of the instance to authenticate against.",
)
@click.option(
    "--sso-url",
    required=False,
    type=str,
    help="URL of your SSO login page to force the authentication flow through your workspace SSO.",
)
@click.option(
    "--token-name",
    required=False,
    type=str,
    help="Name of new token.",
)
@click.option(
    "--lifetime",
    required=False,
    type=click.IntRange(0),
    default=None,
    help="Number of days before the token expires. 0 means the token never expires.",
)
@click.pass_context
def login_cmd(
    ctx: click.Context,
    method: str,
    instance: Optional[str],
    token_name: Optional[str],
    lifetime: Optional[int],
    sso_url: Optional[str],
) -> int:
    """
    Authenticate with a GitGuardian workspace.
    A successful authentication results in a personal access token.
    This token is stored in your configuration and used to authenticate your future requests.

    The default authentication method is "web".
    ggshield launches a web browser to authenticate you to your GitGuardian workspace,
    then automatically generates a token on your behalf.

    Alternatively, you can use `--method token` to authenticate using an already existing token.
    The minimum required scope for the token is `scan`.
    """
    config: Config = ctx.obj["config"]

    if sso_url is not None and method != "web":
        raise click.BadParameter(
            "--sso-url is reserved for the web login method.", param_hint="sso-url"
        )

    if method == "token":

        if instance:
            config.set_cmdline_instance_name(instance)
        instance = config.instance_name
        # Override instance to make sure we get a normalized instance name
        instance_config = config.auth_config.get_or_create_instance(
            instance_name=instance
        )
        token = click.prompt("Enter your GitGuardian API token", hide_input=True)
        if not token:
            raise click.ClickException("No API token was provided.")

        # enforce using the token (and not use config default)
        client = create_client(api_key=token, api_url=config.api_url)
        response = client.get(endpoint="token")
        if not response.ok:
            raise click.ClickException("Authentication failed with token.")

        api_token_data = response.json()
        scopes = api_token_data["scope"]
        if "scan" not in scopes:
            raise click.ClickException("This token does not have the scan scope.")

        account_config = AccountConfig(
            workspace_id=api_token_data.get("account_id"),
            token=token,
            expire_at=api_token_data.get("expire_at"),
            token_name=api_token_data.get("name", ""),
            type=api_token_data.get("type", ""),
        )

        instance_config.account = account_config
        config.auth_config.save()
        click.echo("Authentication was successful.")
        return 0

    if method == "web":
        instance, login_path = validate_login_path(instance=instance, sso_url=sso_url)
        if instance:
            config.set_cmdline_instance_name(instance)
        defined_instance = config.instance_name
        # Override instance to make sure we get a normalized instance name

        check_instance_has_enabled_flow(config=config)

        instance_config = config.auth_config.get_or_create_instance(
            instance_name=defined_instance
        )
        OAuthClient(config, defined_instance).oauth_process(
            token_name=token_name, lifetime=lifetime, login_path=login_path
        )
    return 0
