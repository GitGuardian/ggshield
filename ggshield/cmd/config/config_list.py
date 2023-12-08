from typing import Any, Tuple

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj

from .constants import DATETIME_FORMAT, FIELDS


@click.command()
@click.pass_context
@add_common_options()
def config_list_cmd(ctx: click.Context, **kwargs: Any) -> int:
    """
    Print the list of configuration keys and values.
    """
    config = ContextObj.get(ctx).config
    default_token_lifetime = config.auth_config.default_token_lifetime

    message_lines = []

    def add_entries(*entries: Tuple[str, Any]):
        for key, value in entries:
            message_lines.append(f"{key}: {value}")

    # List global values
    for field in FIELDS.values():
        config_obj = config.auth_config if field.auth_config else config.user_config
        value = getattr(config_obj, field.name)
        add_entries((field.name, value))
    message_lines.append("")

    # List instance values
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
            workspace_id = token = token_name = expiry = "not set"

        _default_token_lifetime = (
            instance.default_token_lifetime
            if instance.default_token_lifetime is not None
            else default_token_lifetime
        )

        message_lines.append(f"[{instance_name}]")
        add_entries(
            ("default_token_lifetime", _default_token_lifetime),
            ("workspace_id", workspace_id),
            ("url", instance.url),
            ("token", token),
            ("token_name", token_name),
            ("expiry", expiry),
        )
        message_lines.append("")

    click.echo("\n".join(message_lines).strip())
    return 0
