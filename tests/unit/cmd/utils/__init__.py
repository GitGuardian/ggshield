from datetime import datetime
from typing import Optional

from ggshield.core.config import AccountConfig, Config, InstanceConfig
from ggshield.core.constants import DEFAULT_INSTANCE_URL


def add_instance_config(
    instance_url: str = DEFAULT_INSTANCE_URL,
    token_name: str = "some token name",
    expiry_date: Optional[datetime] = None,
    with_account: Optional[bool] = True,
    default_token_lifetime: Optional[int] = None,
):
    """
    Creates an InstanceConfig with the provided arguments and adds it to the config
    """
    if with_account:
        account_config = AccountConfig(
            workspace_id=1,
            token="some token",
            expire_at=expiry_date,
            token_name=token_name,
            type="",
        )
    else:
        account_config = None

    instance_config = InstanceConfig(
        account=account_config,
        url=instance_url,
        default_token_lifetime=default_token_lifetime,
    )
    config = Config()
    config.auth_config.instances.append(instance_config)
    config.save()
