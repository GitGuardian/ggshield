import logging
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, cast

import marshmallow_dataclass
from pygitguardian.models_utils import FromDictMixin, ToDictMixin

from ggshield.core import ui
from ggshield.core.config.token_store import (
    KEYRING_SENTINEL,
    Keystore,
    KeystoreError,
    get_keystore,
)
from ggshield.core.config.utils import (
    get_auth_config_filepath,
    load_yaml_dict,
    replace_dash_in_keys,
    save_yaml_dict,
)
from ggshield.core.errors import (
    AuthExpiredError,
    MissingTokenError,
    UnknownInstanceError,
)
from ggshield.utils.datetime import datetime_from_isoformat


logger = logging.getLogger(__name__)


@dataclass
class AccountConfig:
    workspace_id: int
    token: str
    type: str
    token_name: str
    expire_at: Optional[datetime]


def _read_token_from_keystore(instance_url: str) -> str:
    """Read a sentinel-marked token from the credential store, "" if unavailable."""
    store = get_keystore()
    if not store.uses_external_storage:
        logger.warning(
            "Token for %s is stored in keyring but keyring is disabled. "
            "Unset GGSHIELD_NO_KEYRING or re-authenticate with "
            "'ggshield auth login'.",
            instance_url,
        )
        return ""

    try:
        token = store.get_token(instance_url)
    except Exception:
        logger.warning(
            "Failed to retrieve token from keyring for %s",
            instance_url,
            exc_info=True,
        )
        return ""

    if token is None:
        logger.warning(
            "Token for %s was expected in keyring but not found. "
            "Re-authenticate with 'ggshield auth login'.",
            instance_url,
        )
        return ""
    return token


@dataclass
class InstanceConfig:
    # Only handle 1 account per instance for the time being
    account: Optional[AccountConfig]
    url: str
    name: Optional[str] = None
    # The token lifetime. If it's set it overrides AuthConfig.default_token_lifetime
    default_token_lifetime: Optional[int] = None

    def __post_init__(self) -> None:
        self._cached_token: Optional[str] = None

    @property
    def expired(self) -> bool:
        return (
            self.account is not None
            and self.account.expire_at is not None
            and self.account.expire_at <= datetime.now(timezone.utc)
        )

    @property
    def token(self) -> str:
        """The account token. The keystore is read on first use only.

        Reading the keystore can show a macOS Keychain dialog, so the read waits
        until a caller needs the token. The account keeps the `__KEYRING__`
        marker, so save() does not write a token that was only read.
        """
        if self.account is None:
            return ""
        if not self.token_in_keystore:
            return self.account.token
        if self._cached_token is None:
            self._cached_token = _read_token_from_keystore(self.url)
        return self._cached_token

    @property
    def token_in_keystore(self) -> bool:
        return self.account is not None and self.account.token == KEYRING_SENTINEL

    def move_token_to_keystore(self, store: Keystore) -> Optional[KeystoreError]:
        """Move a clear-text token to the keystore.

        Return the error when the keystore refuses the token, and None otherwise.
        """
        if self.account is None or not self.account.token or self.token_in_keystore:
            return None
        try:
            store.store_token(self.url, self.account.token)
        except KeystoreError as exc:
            logger.debug("Failed to store token for %s", self.url, exc_info=True)
            return exc
        self._cached_token = self.account.token
        self.account.token = KEYRING_SENTINEL
        return None

    def init_account(self, token: str, token_data: Dict[str, Any]) -> None:
        """Initialize our account based on the token and the data received from the
        `token` endpoint"""
        expire_at_str = token_data.get("expire_at")
        expire_at = (
            None if expire_at_str is None else datetime_from_isoformat(expire_at_str)
        )
        self.account = AccountConfig(
            workspace_id=cast(int, token_data["account_id"]),
            token=token,
            expire_at=expire_at,
            token_name=token_data["name"],
            type=token_data["type"],
        )
        self._cached_token = None


def prepare_auth_config_dict_for_parse(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Since we support only one account for now, turn instances[].accounts keys into a
    single instances[].account key.

    Stop if there is not exactly one account.

    We replace `-` with `_` for compatibility reasons.
    """
    replace_dash_in_keys(data)
    data = deepcopy(data)
    try:
        instances = data["instances"]
    except KeyError:
        return data

    for instance in instances:
        accounts = instance.pop("accounts")
        if len(accounts) != 1:
            raise ValueError(
                f"Each GitGuardian instance should have exactly one account, got {len(accounts)}"
            )
        instance["account"] = accounts[0]

    return data


def prepare_auth_config_dict_for_save(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Does the opposite of `prepare_auth_config_dict_for_parse`: turn the
    instances[].account key into instances[].accounts keys.
    """
    data = deepcopy(data)
    try:
        instances = data["instances"]
    except KeyError:
        return data

    for instance in instances:
        account = instance.pop("account")
        instance["accounts"] = [account]

    return data


@dataclass
class AuthConfig(FromDictMixin, ToDictMixin):
    """
    Holds all declared GitGuardian instances and their tokens.
    Knows how to load and save them from the YAML file at get_auth_config_filepath().
    """

    default_token_lifetime: Optional[int] = None
    instances: List[InstanceConfig] = field(default_factory=list)

    @classmethod
    def load(cls) -> "AuthConfig":
        """Load the auth config from the app config file.

        Tokens marked with the keyring sentinel stay unresolved: the credential
        store is only read by :attr:`InstanceConfig.token`, so a command that
        needs no token never prompts for one.
        """
        config_path = get_auth_config_filepath()

        data = load_yaml_dict(config_path)
        if data:
            data = prepare_auth_config_dict_for_parse(data)
            return cls.from_dict(data)
        return cls()

    def save(self) -> None:
        """Save the config and move clear-text tokens to the keystore.

        A token that the keystore refuses stays in clear text in the file. A
        warning names the instance and the file.
        """
        config_path = get_auth_config_filepath()
        store = get_keystore()
        if store.uses_external_storage:
            for inst in self.instances:
                error = inst.move_token_to_keystore(store)
                if error is not None:
                    ui.display_warning(
                        error.write_failure_message(inst.url, str(config_path))
                    )

        data = prepare_auth_config_dict_for_save(self.to_dict())
        save_yaml_dict(data, config_path, restricted=True)

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
        token = instance.token
        if not token:
            raise MissingTokenError(instance=instance_name)
        return token

    def forget_account(self, instance_name: str) -> None:
        instance = self.get_instance(instance_name)
        store = get_keystore()
        if store.uses_external_storage:
            try:
                store.delete_token(instance.url)
            except Exception:
                logger.warning(
                    "Failed to delete token from keyring for %s",
                    instance.url,
                    exc_info=True,
                )
        instance.account = None


AuthConfig.SCHEMA = marshmallow_dataclass.class_schema(AuthConfig)()
