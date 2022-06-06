import click
from requests.exceptions import ConnectionError

from ggshield.core.client import create_client
from ggshield.core.config import Config
from ggshield.core.utils import dashboard_to_api_url

from .utils import CONNECTION_ERROR_MESSAGE


@click.command()
@click.option(
    "--instance",
    required=False,
    type=str,
    help="URL of the instance to logout from.",
)
@click.option(
    "--revoke/--no-revoke",
    is_flag=True,
    default=True,
    help="Whether the token should be revoked on logout before being removed from the configuration.",
)
@click.option("--all", "all_", is_flag=True, help="Iterate over every saved tokens.")
@click.pass_context
def logout_cmd(ctx: click.Context, instance: str, revoke: bool, all_: bool) -> int:
    """
    Remove authentication for a GitGuardian instance.
    A successful logout results in the deletion of personal access token stored in the configuration.
    By default, the token will be revoked unless `--no-revoke` option is specified.

    If not specified, ggshield will logout from the default instance.
    The `--all` option can be used if you want to logout from all your GitGuardian instances.
    """
    config = ctx.obj["config"]

    if all_:
        for _instance in config.auth_config.instances:
            logout(config, _instance.url, revoke=revoke)
    else:
        if not instance:
            instance = config.instance_name
        logout(config, instance, revoke=revoke)
    return 0


def logout(config: Config, instance_url: str, revoke: bool) -> None:
    check_account_config_exists(config, instance_url)
    if revoke:
        revoke_token(config, instance_url)
    delete_account_config(config, instance_url)

    click.echo(
        f"Successfully logged out for instance {instance_url}\n\n"
        f"Your personal access token has been{' revoked and' if revoke else ''} "
        "removed from your configuration."
    )


def check_account_config_exists(config: Config, instance_url: str) -> None:
    instance = config.auth_config.get_instance(instance_url)
    if instance.account is None:
        raise click.ClickException(
            f"No token found for instance {instance_url}\n"
            "First try to login by running:\n"
            "  ggshield auth login"
        )


def revoke_token(config: Config, instance_url: str) -> None:

    instance = config.auth_config.get_instance(instance_url)

    assert instance.account is not None
    token = instance.account.token

    client = create_client(
        token,
        dashboard_to_api_url(instance_url),
        allow_self_signed=config.allow_self_signed,
    )
    try:
        response = client.post(endpoint="token/revoke")
    except ConnectionError:
        raise click.ClickException(CONNECTION_ERROR_MESSAGE)

    if response.status_code != 204:
        raise click.ClickException(
            "Could not perform the logout command because your token is already revoked or invalid.\n"
            "Please try with the following command:\n"
            "  ggshield auth logout --no-revoke"
        )


def delete_account_config(config: Config, instance: str) -> None:
    instance_config = config.auth_config.get_instance(instance)
    account_config = instance_config.account

    assert account_config is not None

    instance_config.account = None
    config.auth_config.set_instance(instance_config)
    config.auth_config.save()
