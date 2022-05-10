from datetime import datetime
from typing import Optional

from ggshield.core.config import AccountConfig, Config, InstanceConfig


def prepare_config(
    instance_url: Optional[str] = None,
    token: Optional[str] = None,
    token_name: Optional[str] = None,
    expiry_date: Optional[datetime] = None,
    with_account: Optional[bool] = True,
    default_token_lifetime: Optional[int] = None,
):
    """
    Helper to save a token in the configuration
    """
    instance_url = instance_url or "https://dashboard.gitguardian.com"
    token = token or "some token name"
    token_name = token_name or "some token name"

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
