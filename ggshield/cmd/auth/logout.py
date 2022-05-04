import click
from requests.exceptions import ConnectionError

from ggshield.core.client import create_client
from ggshield.core.config import Config
from ggshield.core.utils import dashboard_to_api_url


REVOKE_FAIL_MESSAGE = (
    "Logout failed due to an error when revoking the token, "
    "you can skip revocation with --no-revoke to bypass"
)


@click.command()
@click.option(
    "--instance",
    required=False,
    type=str,
    help="URL of the instance to logout from.",
)
@click.pass_context
def logout_cmd(ctx: click.Context, instance: str) -> int:
    """
    Delete saved authentication details for the specified instance (or default instance if not specified)
    By default, this will also try to revoke found tokens unless --no-revoke is specified.\n
    If --all is specified, it will iterate over all instances.
    """

    config = ctx.obj["config"]

    if not instance:
        instance = config.instance_name

    check_account_config_exists(config, instance)
    revoke_token(config, instance)
    logout(config, instance)
    return 0


def check_account_config_exists(config: Config, instance_url: str) -> None:
    instance = config.auth_config.get_instance(instance_url)
    if instance.account is None:
        raise click.ClickException(f"No token found for instance {instance_url}.")


def revoke_token(config: Config, instance_url: str) -> None:

    instance = config.auth_config.get_instance(instance_url)

    assert instance.account is not None
    token = instance.account.token
    token_name = instance.account.token_name

    client = create_client(
        token,
        dashboard_to_api_url(instance_url),
        allow_self_signed=config.allow_self_signed,
    )
    try:
        response = client.post(endpoint="token/revoke")
    except ConnectionError:
        raise click.ClickException(REVOKE_FAIL_MESSAGE)

    if response.status_code != 204:
        raise click.ClickException(REVOKE_FAIL_MESSAGE)

    click.echo(f"Personal Access Token {token_name} has been revoked")


def logout(config: Config, instance: str) -> None:
    instance_config = config.auth_config.get_instance(instance)
    account_config = instance_config.account

    assert account_config is not None

    instance_config.account = None
    config.auth_config.set_instance(instance_config)
    config.save()

    click.echo(f"Logged out from instance {instance}")
