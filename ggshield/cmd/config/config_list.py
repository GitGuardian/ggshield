import json
from typing import Any, Tuple

import click

from ggshield.cmd.utils.common_options import add_common_options, json_option
from ggshield.cmd.utils.context_obj import ContextObj

from .constants import DATETIME_FORMAT, FIELDS


@click.command()
@click.pass_context
@json_option
@add_common_options()
def config_list_cmd(ctx: click.Context, **kwargs: Any) -> int:
    """
    Print the list of configuration keys and values.
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    default_token_lifetime = config.auth_config.default_token_lifetime

    # Initialize the structure for JSON output
    config_data = {"instances": [], "global_values": {}}

    def add_global_entries(*entries: Tuple[str, Any]):
        for key, value in entries:
            config_data["global_values"][key] = value

    for field in FIELDS.values():
        config_obj = config.auth_config if field.auth_config else config.user_config
        value = getattr(config_obj, field.name)
        add_global_entries((field.name, value))

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

        instance_info = {
            "default_token_lifetime": _default_token_lifetime,
            "workspace_id": workspace_id,
            "url": instance.url,
            "token": token,
            "token_name": token_name,
            "expiry": expiry,
        }
        config_data["instances"].append(
            {"instance_name": instance_name, **instance_info}
        )

    if ctx_obj.use_json:
        click.echo(json.dumps(config_data, indent=2))
    else:
        message_lines = []

        for key, value in config_data["global_values"].items():
            message_lines.append(f"{key}: {value}")
        message_lines.append("")

        for instance in config_data["instances"]:
            message_lines.append(f"[{instance['instance_name']}]")
            for key, value in instance.items():
                if key != "instance_name":
                    message_lines.append(f"{key}: {value}")
            message_lines.append("")

        click.echo("\n".join(message_lines).strip())

    return 0
