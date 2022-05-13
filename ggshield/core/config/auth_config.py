from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Union

from ggshield.core.config.errors import (
    AuthExpiredError,
    MissingTokenError,
    UnknownInstanceError,
)
from ggshield.core.config.utils import (
    YAMLFileConfig,
    custom_asdict,
    ensure_path_exists,
    get_auth_config_dir,
    get_auth_config_filepath,
    load_yaml,
)


@dataclass
class AccountConfig:
    workspace_id: int
    token: str
    type: str
    token_name: str
    expire_at: Optional[datetime]

    def __post_init__(self) -> None:
        if self.expire_at is not None and not isinstance(self.expire_at, datetime):
            # Allow passing expire_at as an isoformat string
            self.expire_at = datetime.strptime(self.expire_at, "%Y-%m-%dT%H:%M:%S%z")  # type: ignore

    def to_dict(self) -> Dict:
        data: Dict = custom_asdict(self, root=True)  # type: ignore
        expire_at = data["expire_at"]
        data["expire_at"] = expire_at.isoformat() if expire_at is not None else None
        return data


@dataclass
class InstanceConfig:
    # Only handle 1 account per instance for the time being
    account: Optional[AccountConfig]
    url: str
    name: Optional[str] = None
    # The token lifetime. If it's set it overrides AuthConfig.default_token_lifetime
    default_token_lifetime: Optional[int] = None

    @classmethod
    def load(cls, data: Dict) -> "InstanceConfig":
        accounts = data["accounts"]
        assert (
            len(accounts) == 1
        ), "Each GitGuardian instance should have exactly one account"

        account = data.pop("accounts")[0]
        data["account"] = AccountConfig(**account) if account is not None else None
        return cls(**data)

    def to_dict(self) -> Union[List, Dict]:
        data: Dict = custom_asdict(self, root=True)  # type: ignore
        data["accounts"] = [data.pop("account")]
        return data

    @property
    def expired(self) -> bool:
        return (
            self.account is not None
            and self.account.expire_at is not None
            and self.account.expire_at <= datetime.now(timezone.utc)
        )


@dataclass
class AuthConfig(YAMLFileConfig):
    """
    Holds all declared GitGuardian instances and their tokens.
    Knows how to load and save them from the YAML file at get_auth_config_filepath().
    """

    default_token_lifetime: Optional[int] = None
    instances: List[InstanceConfig] = field(default_factory=list)

    @classmethod
    def load(cls) -> "AuthConfig":
        """Load the auth config from the app config file"""
        config_path = get_auth_config_filepath()
        data = load_yaml(config_path)
        if data:
            data["instances"] = [
                InstanceConfig.load(instance_config)
                for instance_config in data["instances"]
            ]
            return cls(**data)
        return cls()

    def save(self) -> None:
        config_path = get_auth_config_filepath()
        ensure_path_exists(get_auth_config_dir())
        self.save_yaml(config_path)

    def get_instance(self, instance_name: str) -> InstanceConfig:
        for instance in self.instances:
            if instance.name == instance_name or instance.url == instance_name:
                return instance
        else:
            raise UnknownInstanceError(instance=instance_name)

    def get_or_create_instance(self, instance_name: str) -> InstanceConfig:
        try:
            instance_config = self.get_instance(instance_name=instance_name)
        except UnknownInstanceError:
            # account is initialized as None because the instance must exist in
            # the config before using the client
            instance_config = InstanceConfig(account=None, url=instance_name)
            self.instances.append(instance_config)
        return instance_config

    def set_instance(self, instance_config: InstanceConfig) -> None:
        instance_name = instance_config.url
        for i, instance in enumerate(self.instances):
            if instance.url == instance_name or instance.name == instance_name:
                self.instances[i] = instance_config
                break
        else:
            self.instances.append(instance_config)

    def get_instance_token(self, instance_name: str) -> str:
        """
        Return the API token associated with the given instance if it is still valid.

        Raise AuthExpiredError if it is not.
        """
        instance = self.get_instance(instance_name)
        if instance.expired:
            raise AuthExpiredError(instance=instance_name)
        if instance.account is None:
            raise MissingTokenError(instance=instance_name)
        return instance.account.token
