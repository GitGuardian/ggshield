import logging
import os
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

import marshmallow_dataclass
from pygitguardian.models_utils import FromDictMixin, ToDictMixin

from ggshield.core import ui
from ggshield.core.config.token_store import (
    KEYRING_SENTINEL,
    TokenStore,
    get_token_store,
    humanize_keyring_error,
    keyring_fix_commands,
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


@dataclass
class InstanceConfig:
    # Only handle 1 account per instance for the time being
    account: Optional[AccountConfig]
    url: str
    name: Optional[str] = None
    # The token lifetime. If it's set it overrides AuthConfig.default_token_lifetime
    default_token_lifetime: Optional[int] = None

    @property
    def expired(self) -> bool:
        return (
            self.account is not None
            and self.account.expire_at is not None
            and self.account.expire_at <= datetime.now(timezone.utc)
        )

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


def read_stored_tokens(config_path: Path) -> Dict[str, str]:
    """Return the ``{instance_url: token}`` mapping currently written on disk.

    The token may be a real cleartext token or the keyring sentinel; this
    reflects where the token is *stored*, before any hydration from the
    credential store. Returns an empty mapping if the file is missing or
    cannot be parsed.
    """
    try:
        data = load_yaml_dict(config_path)
        if not data:
            return {}
        data = prepare_auth_config_dict_for_parse(data)
    except Exception:
        return {}
    tokens: Dict[str, str] = {}
    for instance in data.get("instances", []):
        url = instance.get("url")
        account = instance.get("account")
        if url and account and account.get("token"):
            tokens[url] = account["token"]
    return tokens


def _replace_tokens_with_sentinel(
    data: Dict[str, Any], fallback_urls: set[str]
) -> None:
    """Replace real tokens with the keyring sentinel in the serialized dict,
    except for instances that failed keyring storage."""
    for instance in data.get("instances", []):
        if instance.get("url") in fallback_urls:
            continue
        for account in instance.get("accounts", []):
            if (
                account is not None
                and account.get("token")
                and account["token"] != KEYRING_SENTINEL
            ):
                account["token"] = KEYRING_SENTINEL


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

        If the active token store is a keyring backend, tokens marked with the
        keyring sentinel are hydrated from the OS credential store.

        When ``GITGUARDIAN_API_KEY`` is set in the environment it overrides any
        stored token in :meth:`Config.get_api_key_and_source`, so we skip the
        keyring access here to avoid prompting the user (e.g. for OS keychain
        unlock) for a credential that will not be used. This matters for
        global ggshield invocations like pre-commit hooks that already supply
        a token via the environment.
        """
        config_path = get_auth_config_filepath()

        data = load_yaml_dict(config_path)
        if data:
            data = prepare_auth_config_dict_for_parse(data)
            instance = cls.from_dict(data)
        else:
            instance = cls()

        if os.environ.get("GITGUARDIAN_API_KEY"):
            return instance

        store = get_token_store()
        if store.uses_external_storage:
            for inst in instance.instances:
                cls._hydrate_from_keyring(store, inst)
        else:
            for inst in instance.instances:
                cls._warn_sentinel_without_keyring(inst)

        return instance

    def save(self) -> None:
        config_path = get_auth_config_filepath()
        store = get_token_store()
        data = prepare_auth_config_dict_for_save(self.to_dict())

        if store.uses_external_storage:
            # Token as it currently is on disk, used to tell a genuine
            # cleartext -> keyring migration apart from a routine re-save.
            prior_tokens = read_stored_tokens(config_path)
            fallback_urls: set[str] = set()
            for inst in self.instances:
                error = self._persist_to_keyring(store, inst, fallback_urls)
                self._report_keyring_outcome(store, inst, prior_tokens, error)
            _replace_tokens_with_sentinel(data, fallback_urls)

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
        if instance.account is None or not instance.account.token:
            raise MissingTokenError(instance=instance_name)
        return instance.account.token

    @staticmethod
    def _hydrate_from_keyring(store: TokenStore, inst: InstanceConfig) -> None:
        if inst.account is None or inst.account.token != KEYRING_SENTINEL:
            return
        try:
            token = store.get_token(inst.url)
        except Exception:
            logger.warning(
                "Failed to retrieve token from keyring for %s",
                inst.url,
                exc_info=True,
            )
            token = None

        if token is not None:
            inst.account.token = token
        else:
            logger.warning(
                "Token for %s was expected in keyring but not found. "
                "Re-authenticate with 'ggshield auth login'.",
                inst.url,
            )
            # Preserve account metadata; only clear the token so
            # that a subsequent save() does not destroy the config.
            inst.account.token = ""

    @staticmethod
    def _warn_sentinel_without_keyring(inst: InstanceConfig) -> None:
        if inst.account is None or inst.account.token != KEYRING_SENTINEL:
            return
        logger.warning(
            "Token for %s is stored in keyring but keyring is disabled. "
            "Unset GGSHIELD_NO_KEYRING or re-authenticate with "
            "'ggshield auth login'.",
            inst.url,
        )
        inst.account.token = ""

    @staticmethod
    def _persist_to_keyring(
        store: TokenStore,
        inst: InstanceConfig,
        fallback_urls: set[str],
    ) -> Optional[str]:
        """Store the instance token in the credential store.

        Returns ``None`` on success or when there is nothing to store, or a
        short error message when the write fails (in which case the URL is
        added to ``fallback_urls`` so the token stays in the config file).
        """
        if (
            inst.account is None
            or not inst.account.token
            or inst.account.token == KEYRING_SENTINEL
        ):
            return None
        try:
            store.store_token(inst.url, inst.account.token)
        except Exception as exc:
            logger.warning(
                "Failed to store token in keyring for %s, storing in config file",
                inst.url,
                exc_info=True,
            )
            fallback_urls.add(inst.url)
            return str(exc)
        return None

    @staticmethod
    def _report_keyring_outcome(
        store: TokenStore,
        inst: InstanceConfig,
        prior_tokens: Dict[str, str],
        error: Optional[str],
    ) -> None:
        """Surface the result of a keyring write to the user.

        On failure, warn that the token stays in plaintext and how to fix it.
        On success, only announce a genuine cleartext -> keyring migration; stay
        silent on routine re-saves and fresh logins to avoid noise.
        """
        if inst.account is None or not inst.account.token:
            return

        if error is not None:
            fix = "\n".join(
                f"  {command}" for command in keyring_fix_commands(inst.url)
            )
            ui.display_warning(
                f"Could not store the token for {inst.url} in the "
                f"{store.backend_name}: {humanize_keyring_error(error)}\n"
                "The token will be stored in cleartext in the config file "
                "instead.\n"
                "Run `ggshield auth status` for details, or fix it now with:\n"
                f"{fix}"
            )
            return

        prior = prior_tokens.get(inst.url)
        was_cleartext = bool(prior) and prior != KEYRING_SENTINEL
        if was_cleartext:
            ui.display_info(
                f"Token for {inst.url} migrated to the {store.backend_name}."
            )


AuthConfig.SCHEMA = marshmallow_dataclass.class_schema(AuthConfig)()
