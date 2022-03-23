import os
from dataclasses import InitVar, asdict, dataclass, field, fields
from datetime import datetime, timedelta
from functools import cached_property
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set

import click
import yaml
from appdirs import user_config_dir

from ggshield.constants import (
    AUTH_CONFIG_FILENAME,
    DEFAULT_API_URL,
    DEFAULT_DASHBOARD_URL,
    DEFAULT_LOCAL_CONFIG_PATH,
    GLOBAL_CONFIG_FILENAMES,
    LOCAL_CONFIG_PATHS,
)
from ggshield.types import IgnoredMatch
from ggshield.utils import isoformat_to_datetime_utc


def replace_in_keys(data: Dict, old_char: str, new_char: str) -> None:
    """Replace old_char with new_char in data keys."""
    for key in list(data):
        if old_char in key:
            new_key = key.replace(old_char, new_char)
            data[new_key] = data.pop(key)


def load_yaml(path: str, raise_exc=False) -> Optional[Dict[str, Any]]:
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
        else:
            return data


def dprint(*args, **kwargs):
    pass


def get_global_path(filename: str) -> str:
    return os.path.join(os.path.expanduser("~"), filename)


class YamlFileConfig:
    """Helper class to define configuration object loaded from a YAML file"""

    def to_dict(self):
        data = asdict(self)
        replace_in_keys(data, old_char="_", new_char="-")
        return data

    @classmethod
    def from_dict(cls, data):
        replace_in_keys(data, old_char="-", new_char="_")
        return cls(**data)

    def update_config(self, data: Dict[str, Any]) -> bool:
        """
        Update the current config
        raise an error if trying to set a field that does not exist
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

    def save_yaml(self, path: str):
        with open(path, "w") as f:
            try:
                stream = yaml.dump(self.to_dict(), indent=2, default_flow_style=False)
                f.write(stream)
            except Exception as e:
                raise click.ClickException(
                    f"Error while saving config in {path}:\n{str(e)}"
                ) from e


@dataclass
class UserConfig(YamlFileConfig):
    api_url: str = DEFAULT_API_URL
    dashboard_url: str = DEFAULT_DASHBOARD_URL
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

    def save(self) -> bool:
        """
        Save config in the first CONFIG_LOCAL or the path it the config was loaded from
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
                dprint(
                    f'loading global config from "{global_config_filename}"...', end=""
                )
                global_config_path = get_global_path(global_config_filename)
                global_data = load_yaml(global_config_path)
                if global_data:
                    dprint("OK")
                else:
                    dprint("FAIL")
                dprint("user_config.paths_ignore", user_config.paths_ignore)
                if global_data and user_config.update_config(global_data):
                    dprint("user_config.paths_ignore", user_config.paths_ignore)
                    break
            for local_config_path in LOCAL_CONFIG_PATHS:
                dprint(f'loading local config from "{local_config_path}"...', end="")
                local_data = load_yaml(local_config_path)
                if local_data:
                    dprint("OK")
                    dprint("local_data", local_data)
                else:
                    dprint("FAIL")
                dprint("user_config.paths_ignore", user_config.paths_ignore)
                if local_data and user_config.update_config(local_data):
                    dprint("user_config.paths_ignore", user_config.paths_ignore)
                    break
        return user_config

    def add_ignored_match(self, secret: dict) -> None:
        """
        Add secret to matches_ignore.
        if it matches an ignore not in dict form, it converts it.
        """
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
    id: int
    url: str
    token: str
    type: str
    token_name: str
    raw_expire_at: InitVar[str]
    expire_at: datetime = None

    def __post_init__(self, raw_expire_at: str):
        self.expire_at = isoformat_to_datetime_utc(raw_expire_at)


@dataclass
class HostConfig:
    name: str
    account: AccountConfig  # Only handle 1 account per host for the time being
    default_token_lifetime: Optional[timedelta] = None

    @classmethod
    def load(cls, data) -> "HostConfig":
        assert len(data["accounts"]) <= 1
        data["account"] = AccountConfig(**data["account"])
        return cls(**data)


def get_auth_config_dir():
    return user_config_dir(appname="ggshield", appauthor="GitGuardian")


def get_auth_config_filepath():
    return os.path.join(get_auth_config_dir(), AUTH_CONFIG_FILENAME)


def ensure_path_exists(dir_path: str):
    Path(dir_path).mkdir(parents=True, exist_ok=True)


@dataclass
class AuthConfig(YamlFileConfig):
    default_host: str = "dashboard.gitguardian.com"
    default_token_lifetime: Optional[int] = None
    hosts: Mapping[str, HostConfig] = field(default_factory=dict)

    @classmethod
    def load(cls) -> "AuthConfig":
        """Load the auth config from the app config file"""
        config_path = get_auth_config_filepath()
        data = load_yaml(config_path)
        if data:
            data["hosts"] = {
                key: HostConfig.load(value) for key, value in data["hosts"].items()
            }
            return cls(**data)
        return cls()

    def save(self):
        config_path = get_auth_config_filepath()
        ensure_path_exists(get_auth_config_dir())
        self.save_yaml(config_path)


def get_attr_mapping(classes):
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
        subconfig = getattr(self, self._attr_mapping[name])
        return getattr(subconfig, name)

    def __setattr__(self, key, value):
        subconfig = getattr(self, self._attr_mapping[key])
        setattr(subconfig, key, value)

    def save(self):
        self.user_config.save()
        self.auth_config.save()

    @cached_property
    def gitguardian_api_key(self) -> Optional[str]:
        api_key = os.getenv("GITGUARDIAN_API_KEY")
        if not api_key:
            raise click.ClickException("GitGuardian API Key is needed.")
        return api_key
