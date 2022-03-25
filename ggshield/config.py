import copy
import os
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple, Type, Union

import click
import yaml
from appdirs import user_config_dir

from ggshield.constants import (
    AUTH_CONFIG_FILENAME,
    DEFAULT_LOCAL_CONFIG_PATH,
    GLOBAL_CONFIG_FILENAMES,
    LOCAL_CONFIG_PATHS,
)
from ggshield.types import IgnoredMatch
from ggshield.utils import api_to_dashboard_url, dashboard_to_api_url


def replace_in_keys(
    data: Union[List, Dict], old_char: str, new_char: str, recursive: bool = True
) -> None:
    """Replace old_char with new_char in data keys."""
    if recursive:
        if isinstance(data, dict):
            for key, value in list(data.items()):
                replace_in_keys(value, old_char=old_char, new_char=new_char)
                if old_char in key:
                    new_key = key.replace(old_char, new_char)
                    data[new_key] = data.pop(key)
        elif isinstance(data, list):
            for element in data:
                replace_in_keys(
                    element, old_char=old_char, new_char=new_char, recursive=True
                )
    else:
        assert isinstance(data, dict)
        for key, value in list(data.items()):
            if old_char in key:
                new_key = key.replace(old_char, new_char)
                data[new_key] = data.pop(key)


def load_yaml(path: str, raise_exc: bool = False) -> Optional[Dict[str, Any]]:
    if not os.path.isfile(path):
        return None

    with open(path, "r") as f:
        try:
            data = yaml.safe_load(f) or {}
        except Exception as e:
            message = f"Parsing error while reading {path}:\n{str(e)}"
            if raise_exc:
                raise click.ClickException(message) from e
            else:
                click.echo(message)
                return None
        else:
            replace_in_keys(data, old_char="-", new_char="_")
            return data


def get_global_path(filename: str) -> str:
    return os.path.join(os.path.expanduser("~"), filename)


def custom_asdict(obj: Any, root: bool = False) -> Union[List, Dict]:
    """
    customization of dataclasses.asdict to allow implementing a "to_dict"
    method for customization.
    root=True skips the first to_dict, to allow calling this function from "to_dict"
    """
    if is_dataclass(obj):
        if not root and hasattr(obj, "to_dict"):
            return obj.to_dict()  # type: ignore
        result = []
        for f in fields(obj):
            value = custom_asdict(getattr(obj, f.name))
            result.append((f.name, value))
        return dict(result)
    elif isinstance(obj, (list, tuple)):
        return type(obj)(custom_asdict(v) for v in obj)  # type: ignore
    elif isinstance(obj, dict):
        return type(obj)((custom_asdict(k), custom_asdict(v)) for k, v in obj.items())
    else:
        return copy.deepcopy(obj)  # type: ignore


class YamlFileConfig:
    """Helper class to define configuration object loaded from a YAML file"""

    def __init__(self, **kwargs: Any) -> None:
        raise NotImplementedError

    def to_dict(self) -> Union[List, Dict]:
        return custom_asdict(self, root=True)

    def update_config(self, data: Dict[str, Any]) -> bool:
        """
        Update the current config, ignoring the unrecognized keys
        """
        field_names = {field_.name for field_ in fields(self)}
        replace_in_keys(data, old_char="-", new_char="_")
        for key, item in data.items():
            if key not in field_names:
                click.echo("Unrecognized key in config: {}".format(key))
                continue
            if isinstance(getattr(self, key), list):
                getattr(self, key).extend(item)
            elif isinstance(getattr(self, key), set):
                getattr(self, key).update(item)
            else:
                setattr(self, key, item)
        return True

    def save_yaml(self, path: str) -> None:
        data = self.to_dict()
        replace_in_keys(data, old_char="_", new_char="-")
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w") as f:
            try:
                stream = yaml.dump(data, indent=2, default_flow_style=False)
                f.write(stream)
            except Exception as e:
                raise click.ClickException(
                    f"Error while saving config in {path}:\n{str(e)}"
                ) from e

    def save(self) -> None:
        raise NotImplementedError

    @classmethod
    def load(cls) -> "YamlFileConfig":
        raise NotImplementedError


@dataclass
class UserConfig(YamlFileConfig):
    api_url: Optional[str] = None
    dashboard_url: Optional[str] = None
    config_path: Optional[str] = None
    all_policies: bool = False
    exit_zero: bool = False
    matches_ignore: List[IgnoredMatch] = field(default_factory=list)
    paths_ignore: Set[str] = field(default_factory=set)
    show_secrets: bool = False
    verbose: bool = False
    allow_self_signed: bool = False
    max_commits_for_hook: int = 50
    banlisted_detectors: Set[str] = field(default_factory=set)
    ignore_default_excludes: bool = False

    def set_env_gitguardian_urls(self) -> None:
        """
        If one of the URL env vars is defined, set them both
        """
        api_url = os.getenv("GITGUARDIAN_API_URL")
        dashboard_url = os.getenv("GITGUARDIAN_URL")
        if api_url is not None:
            if dashboard_url is None:
                dashboard_url = api_to_dashboard_url(api_url)
            self.api_url = api_url
            self.dashboard_url = dashboard_url
        elif dashboard_url is not None:
            api_url = dashboard_to_api_url(dashboard_url)
            self.api_url = api_url
            self.dashboard_url = dashboard_url

    def update_config(self, data: Dict[str, Any]) -> bool:
        """
        URLs should always be both set together to make sure they belong
        to the same instance
        """
        if "dashboard_url" in data and "api_url" not in data:
            data["api_url"] = dashboard_to_api_url(data["dashboard_url"])
        elif "dashboard_url" not in data and "api_url" in data:
            data["dashboard_url"] = api_to_dashboard_url(data["api_url"])
        return super().update_config(data)

    def save(self) -> None:
        """
        Save config in the first CONFIG_LOCAL or the path it was loaded from
        If no local config file, creates a local .gitguardian.yaml
        """
        config_path = self.config_path or DEFAULT_LOCAL_CONFIG_PATH
        self.save_yaml(config_path)

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "UserConfig":
        """
        Load the various user configs files to create a UserConfig object:
        - global user configuration file (in the home)
        - local user configuration file (in the repository)

        The user configuration path can be overriden
        """

        user_config = UserConfig()
        # Load the user config
        if config_path:
            data = load_yaml(config_path) or {}
            data["local_config_path"] = config_path
            user_config.update_config(data)
        else:
            for global_config_filename in GLOBAL_CONFIG_FILENAMES:
                global_config_path = get_global_path(global_config_filename)
                global_data = load_yaml(global_config_path)
                if global_data and user_config.update_config(global_data):
                    break
            for local_config_path in LOCAL_CONFIG_PATHS:
                local_data = load_yaml(local_config_path)
                if local_data and user_config.update_config(local_data):
                    break
        # Env variables have priority over the local/global configs
        user_config.set_env_gitguardian_urls()
        return user_config

    def add_ignored_match(self, secret: Dict) -> None:
        """
        Add secret to matches_ignore.
        if it matches an ignore not in dict form, it converts it.
        """
        found = False
        for i, match in enumerate(self.matches_ignore):
            if isinstance(match, dict):
                if match["match"] == secret["match"]:
                    found = True
                    # take the opportunity to name the ignored match
                    if not match["name"]:
                        match["name"] = secret["name"]
            elif isinstance(match, str):
                if match == secret["match"]:
                    found = True
                    self.matches_ignore[i] = secret
            else:
                raise click.ClickException("Wrong format found in ignored matches")
        if not found:
            self.matches_ignore.append(secret)


@dataclass
class AccountConfig:
    account_id: int
    token: str
    type: str
    token_name: str
    expire_at: Optional[datetime]

    def __post_init__(self) -> None:
        if self.expire_at is not None and not isinstance(self.expire_at, datetime):
            # Allow passing expire_at as an isoformat string
            self.expire_at = datetime.fromisoformat(self.expire_at.replace("Z", "+00:00"))  # type: ignore

    def to_dict(self) -> Dict:
        data: Dict = custom_asdict(self, root=True)  # type: ignore
        expire_at = data["expire_at"]
        data["expire_at"] = expire_at.isoformat() if expire_at is not None else None
        return data


@dataclass
class InstanceConfig:
    account: AccountConfig  # Only handle 1 account per instance for the time being
    url: str
    name: Optional[str] = None
    default_token_lifetime: Optional[timedelta] = None

    @classmethod
    def load(cls, data: Dict) -> "InstanceConfig":
        accounts = data["accounts"]
        assert (
            len(accounts) == 1
        ), "Each GitGuardian instance should have exactly one account"
        data["account"] = AccountConfig(**data.pop("accounts")[0])
        return cls(**data)

    def to_dict(self) -> Union[List, Dict]:
        data: Dict = custom_asdict(self, root=True)  # type: ignore
        data["accounts"] = [data.pop("account")]
        return data

    @property
    def expired(self) -> bool:
        return (
            self.account.expire_at is not None
            and self.account.expire_at <= datetime.now()
        )


def get_auth_config_dir() -> str:
    return user_config_dir(appname="ggshield", appauthor="GitGuardian")


def get_auth_config_filepath() -> str:
    return os.path.join(get_auth_config_dir(), AUTH_CONFIG_FILENAME)


def ensure_path_exists(dir_path: str) -> None:
    Path(dir_path).mkdir(parents=True, exist_ok=True)


@dataclass
class AuthConfig(YamlFileConfig):
    current_token: Optional[str] = None
    current_instance: Optional[str] = None
    default_instance: str = "https://dashboard.gitguardian.com"
    default_token_lifetime: Optional[int] = None
    instances: Mapping[str, InstanceConfig] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.current_token = os.getenv("GITGUARDIAN_API_KEY", self.current_token)

    def to_dict(self) -> Dict:
        """Remove temporary values when serializing before saving"""
        data: Dict = super().to_dict()  # type: ignore
        data.pop("current_instance")
        data.pop("current_token")
        return data

    @classmethod
    def load(cls) -> "AuthConfig":
        """Load the auth config from the app config file"""
        config_path = get_auth_config_filepath()
        data = load_yaml(config_path)
        if data:
            data["instances"] = {
                key: InstanceConfig.load(value)
                for key, value in data["instances"].items()
            }
            return cls(**data)
        return cls()

    def save(self) -> None:
        config_path = get_auth_config_filepath()
        ensure_path_exists(get_auth_config_dir())
        self.save_yaml(config_path)

    def get_instance(self, instance_name: str) -> InstanceConfig:
        try:
            instance = self.instances[instance_name]
        except KeyError:
            raise click.ClickException(f"Unrecognized instance: '{instance_name}'")
        return instance

    def get_instance_token(self, instance_name: str) -> str:
        """
        Return the API token associated with the given instance if it is still valid.
        """
        instance = self.get_instance(instance_name)
        if instance.expired:
            raise click.ClickException(
                f"Instance '{instance_name}' authentication expired, please authenticate again."
            )
        return instance.account.token


def get_attr_mapping(
    classes: Iterable[Tuple[Type[YamlFileConfig], str]]
) -> Dict[str, str]:
    """
    Return a mapping from a field name to the correct class
    raise an AssertionError if there is a field name collision
    """
    mapping = {}
    for klass, attr_name in classes:
        for field_ in fields(klass):
            assert field_.name not in mapping, f"Conflict with field '{field_.name}'"
            mapping[field_.name] = attr_name
    return mapping


class Config:
    user_config: UserConfig
    auth_config: AuthConfig
    _attr_mapping: Mapping[str, str] = get_attr_mapping(
        [(UserConfig, "user_config"), (AuthConfig, "auth_config")]
    )

    def __init__(self, config_path: Optional[str] = None):
        # bypass __setattr__ to avoid infinite recursion
        self.__dict__["user_config"] = UserConfig.load(config_path=config_path)
        self.__dict__["auth_config"] = AuthConfig.load()

    def __getattr__(self, name: str) -> Any:
        try:
            subconfig_name = self._attr_mapping[name]
        except KeyError:
            raise AttributeError(
                f"'{self.__class__.__name__}' has no attribute '{name}'"
            )
        subconfig = getattr(self, subconfig_name)
        return getattr(subconfig, name)

    def __setattr__(self, key: str, value: Any) -> None:
        subconfig = getattr(self, self._attr_mapping[key])
        setattr(subconfig, key, value)

    def save(self) -> None:
        self.user_config.save()
        self.auth_config.save()

    @property
    def instance_name(self) -> str:
        """
        The instance name (defaulting to URL) in the auth config of the selected instance
        priority order is:
        - manually set (in auth_config.current_instance)
        - env var (in auth_config.current_instance)
        - in local user config (in user_config.dashboard_url)
        - in global user config (in user_config.dashboard_url)
        - the default instance (in auth_config.default_instance)
        """
        instance_name = self.auth_config.current_instance
        if instance_name is None:
            instance_name = self.user_config.dashboard_url
            if instance_name is None:
                instance_name = self.auth_config.default_instance
        return instance_name

    @property
    def api_url(self) -> str:
        """
        The API URL to use to use the API
        It's the API URL from the configured instance
        """
        instance_name = self.auth_config.current_instance
        if instance_name is None:
            api_url = self.user_config.api_url
            if api_url is None:
                # TODO change when the default_instance can be a name instead of just a URL
                api_url = dashboard_to_api_url(self.auth_config.default_instance)
        else:
            api_url = dashboard_to_api_url(
                self.auth_config.get_instance(instance_name).url
            )
        return api_url

    @property
    def dashboard_url(self) -> str:
        """
        The dashboard URL to use to use the dashboard
        It's the dashboard URL from the configured instance
        """
        instance_name = self.auth_config.current_instance
        if instance_name is None:
            dashboard_url = self.user_config.dashboard_url
            if dashboard_url is None:
                # TODO change when the default_instance can be a name instead of just a URL
                dashboard_url = self.auth_config.default_instance
        else:
            dashboard_url = self.auth_config.get_instance(instance_name).url
        return dashboard_url

    @property
    def api_key(self) -> Optional[str]:
        """
        The API key to use
        priority order is
        - manually set (in auth_config.current_token)
        - env var (in auth_config.current_token)
        - the api key from the selected instance
        """
        api_key = self.auth_config.current_token
        if api_key is None:
            instance_name = self.instance_name
            api_key = self.auth_config.get_instance_token(instance_name)
            if api_key is None:
                raise click.ClickException("GitGuardian API key is needed.")
        return api_key

    def add_ignored_match(self, *args: Any, **kwargs: Any) -> None:
        return self.user_config.add_ignored_match(*args, **kwargs)
