import click

from ggshield.core.config import Config

from .constants import DATETIME_FORMAT


@click.command()
@click.pass_context
def config_list_cmd(ctx: click.Context) -> int:
    """
    List all auth configurations.
    """
    config: Config = ctx.obj["config"]

    message = ""
    for instance in config.auth_config.instances:
        instance_name = instance.name or instance.url

        if instance.account is not None:
            workspace_id = instance.account.workspace_id
            token = instance.account.token
            token_name = instance.account.token_name
            expire_at = instance.account.expire_at
            expiry = (
                expire_at.strftime(DATETIME_FORMAT)
                if expire_at is not None
                else "never"
            )
        else:
            workspace_id = token = token_name = expiry = "not set"  # type: ignore

        message_lines = [
            f"[{instance_name}]",
            f"default_token_lifetime: {instance.default_token_lifetime}",
            f"workspace_id: {workspace_id}",
            f"url: {instance.url}",
            f"token: {token}",
            f"token_name: {token_name}",
            f"expiry: {expiry}",
        ]
        message += ("\n".join(message_lines)) + "\n\n"

    click.echo(message[:-2])
    return 0
