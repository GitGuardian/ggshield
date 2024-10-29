import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import click

from ggshield.cmd.utils.common_options import (
    add_common_options,
    json_option,
    text_json_format_option,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.config.auth_config import InstanceConfig

from .constants import DATETIME_FORMAT, FIELDS


@dataclass
class InstanceInfo:
    instance_name: str
    default_token_lifetime: Optional[int]
    workspace_id: Any
    url: str
    token: str
    token_name: str
    expiry: str


@dataclass
class ConfigData:
    instances: List[InstanceInfo] = field(default_factory=list)
    global_values: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "instances": [instance.__dict__ for instance in self.instances],
            "global_values": self.global_values,
        }


def get_instance_info(
    instance: InstanceConfig, default_token_lifetime: Any
) -> InstanceInfo:
    """Helper function to extract instance information."""
    instance_name = instance.name or instance.url
    account = instance.account

    if account is not None:
        workspace_id = account.workspace_id
        token = account.token
        token_name = account.token_name
        expire_at = account.expire_at
        expiry = expire_at.strftime(DATETIME_FORMAT) if expire_at else "never"
    else:
        workspace_id = token = token_name = expiry = "not set"

    _default_token_lifetime = instance.default_token_lifetime or default_token_lifetime

    return InstanceInfo(
        instance_name=instance_name,
        default_token_lifetime=_default_token_lifetime,
        workspace_id=workspace_id,
        url=instance.url,
        token=token,
        token_name=token_name,
        expiry=expiry,
    )


@click.command()
@click.pass_context
@json_option
@text_json_format_option
@add_common_options()
def config_list_cmd(ctx: click.Context, **kwargs: Any) -> int:
    """
    Print the list of configuration keys and values.
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    default_token_lifetime = config.auth_config.default_token_lifetime

    config_data = ConfigData()
    for config_field in FIELDS.values():
        config_obj = (
            config.auth_config if config_field.auth_config else config.user_config
        )
        value = getattr(config_obj, config_field.name)
        config_data.global_values[config_field.name] = value

    config_data.instances = [
        get_instance_info(instance, default_token_lifetime)
        for instance in config.auth_config.instances
    ]

    if ctx_obj.use_json:
        click.echo(json.dumps(config_data.as_dict()))
    else:
        message_lines = [
            f"{key}: {value}" for key, value in config_data.global_values.items()
        ]
        message_lines.append("")
        for instance in config_data.instances:
            message_lines.append(f"[{instance.instance_name}]")
            for key, value in instance.__dict__.items():
                if key != "instance_name":
                    message_lines.append(f"{key}: {value}")
            message_lines.append("")

        click.echo("\n".join(message_lines).strip())

    return 0
