import re
from typing import Any, List, Optional, Tuple

import click
import requests

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.client import create_client
from ggshield.core.config import Config
from ggshield.core.constants import DEFAULT_INSTANCE_URL
from ggshield.core.errors import UnexpectedError
from ggshield.core.url_utils import clean_url
from ggshield.verticals.auth import OAuthClient


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
        raise UnexpectedError("instance and SSO URL params do not match")
    return instance, sso_login_path


def print_default_instance_message(config: Config) -> None:
    """If the instance used is not defined as the default instance, show a message
    explaining how to make it the default instance."""
    cli_instance = config.cmdline_instance_name
    if not cli_instance or cli_instance == DEFAULT_INSTANCE_URL:
        return
    click.echo(
        "\nTo make ggshield always use this instance,"
        f' run "ggshield config set instance {cli_instance}".'
    )


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
    metavar="URL",
)
@click.option(
    "--scopes",
    required=False,
    type=str,
    help=(
        "Space-separated list of extra scopes to request in addition to the default"
        " `scan` scope."
    ),
    metavar="SCOPES",
)
@click.option(
    "--sso-url",
    required=False,
    type=str,
    help="URL of your SSO login page to force the authentication flow through your workspace SSO.",
    metavar="URL",
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
    metavar="DAYS",
)
@add_common_options()
@click.pass_context
def login_cmd(
    ctx: click.Context,
    method: str,
    instance: Optional[str],
    scopes: Optional[str],
    token_name: Optional[str],
    lifetime: Optional[int],
    sso_url: Optional[str],
    **kwargs: Any,
) -> int:
    """
    Authenticate with a GitGuardian instance.

    A successful authentication results in a personal access token.
    This token is stored in your configuration and used to authenticate your future requests.

    The default authentication method is `web`.
    ggshield launches a web browser to authenticate you to your GitGuardian instance,
    then automatically generates a token on your behalf.

    Alternatively, you can use `--method token` to authenticate using an already existing token.
    The minimum required scope for the token is `scan`.

    By default, the created token will have the `scan` scope. Use the `--scopes` option
    to grant the token extra scopes. You can find the list of available scopes in
    [GitGuardian API documentation][1].

    If a valid personal access token is already configured, this command simply displays
    a success message indicating that ggshield is already ready to use.

    [1]: https://docs.gitguardian.com/api-docs/authentication#scopes
    """
    config = ContextObj.get(ctx).config

    if method != "web":
        if sso_url is not None:
            raise click.BadParameter(
                "--sso-url is reserved for the web login method.", param_hint="sso-url"
            )

        if scopes is not None:
            raise click.BadParameter(
                "--scopes is reserved for the web login method.", param_hint="scopes"
            )

    if method == "token":
        token_login(config, instance)
        return 0

    if method == "web":
        extra_scopes = scopes.split(" ") if scopes else None
        web_login(config, instance, token_name, lifetime, sso_url, extra_scopes)
        return 0

    return 1


def token_login(config: Config, instance: Optional[str]) -> None:
    if instance:
        config.cmdline_instance_name = instance
    instance = config.instance_name
    # Override instance to make sure we get a normalized instance name
    instance_config = config.auth_config.get_or_create_instance(instance_name=instance)

    token = None
    if not click.get_text_stream("stdin").isatty():
        # Read from stdin only when the stdin is not connected to terminal, but is provided from the pipe
        token = click.get_text_stream("stdin").read().strip()

    # Prompt if the token was not provided with stdin
    if not token:
        token = click.prompt("Enter your GitGuardian API token", hide_input=True)

    if not token:
        raise UnexpectedError("No API token was provided.")

    # enforce using the token (and not use config default)
    client = create_client(
        api_key=token,
        api_url=config.api_url,
        allow_self_signed=config.user_config.insecure,
    )
    try:
        response = client.get(endpoint="token")
    except requests.exceptions.ConnectionError as e:
        if "Failed to resolve" in str(e):
            raise click.UsageError(f"Invalid instance: {instance}.")
        else:
            raise UnexpectedError(f"Failed to connect to {instance}.") from e

    if not response.ok:
        raise UnexpectedError("Authentication failed with token.")

    api_token_data = response.json()
    scopes = api_token_data["scope"]
    if "scan" not in scopes:
        raise UnexpectedError("This token does not have the scan scope.")

    instance_config.init_account(token, api_token_data)
    config.auth_config.save()
    click.echo("Authentication was successful.")
    print_default_instance_message(config)


def web_login(
    config: Config,
    instance: Optional[str],
    token_name: Optional[str],
    lifetime: Optional[int],
    sso_url: Optional[str],
    extra_scopes: Optional[List[str]],
) -> None:
    instance, login_path = validate_login_path(instance=instance, sso_url=sso_url)
    if instance:
        config.cmdline_instance_name = instance
    defined_instance = config.instance_name
    # Override instance to make sure we get a normalized instance name
    config.auth_config.get_or_create_instance(instance_name=defined_instance)

    client = OAuthClient(config, defined_instance)

    if client.check_existing_token():
        # skip the process if a valid token is already saved
        return

    client.oauth_process(
        token_name=token_name,
        lifetime=lifetime,
        login_path=login_path,
        extra_scopes=extra_scopes,
    )
    print_default_instance_message(config)
