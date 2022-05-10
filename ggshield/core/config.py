import copy
import os
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple, Type, Union

import click
import yaml
from appdirs import user_config_dir

from ggshield.core.constants import (
    AUTH_CONFIG_FILENAME,
    DEFAULT_DASHBOARD_URL,
    DEFAULT_LOCAL_CONFIG_PATH,
    GLOBAL_CONFIG_FILENAMES,
    LOCAL_CONFIG_PATHS,
)
from ggshield.core.types import IgnoredMatch
from ggshield.core.utils import api_to_dashboard_url, clean_url, dashboard_to_api_url


def replace_in_keys(data: Union[List, Dict], old_char: str, new_char: str) -> None:
    """Replace old_char with new_char in data keys."""
    if isinstance(data, dict):
        for key, value in list(data.items()):
            replace_in_keys(value, old_char=old_char, new_char=new_char)
            if old_char in key:
                new_key = key.replace(old_char, new_char)
                data[new_key] = data.pop(key)
    elif isinstance(data, list):
        for element in data:
            replace_in_keys(element, old_char=old_char, new_char=new_char)


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
        result = {}
        for f in fields(obj):
            result[f.name] = custom_asdict(getattr(obj, f.name))
        return result
    elif isinstance(obj, (list, tuple)):
        return type(obj)(custom_asdict(v) for v in obj)  # type: ignore
    elif isinstance(obj, dict):
        return type(obj)((k, custom_asdict(v)) for k, v in obj.items())
    elif isinstance(obj, set):
        # Turn sets into lists so that YAML serialization does not turn them into YAML
        # unordered sets
        return [custom_asdict(v) for v in obj]
    else:
        return copy.deepcopy(obj)  # type: ignore


class YAMLFileConfig:
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


@dataclass
class UserConfig(YAMLFileConfig):
    """
    Holds all ggshield settings defined by the user in the .gitguardian.yaml files
    (local and global).
    """

    instance: Optional[str] = None
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

    def update_config(self, data: Dict[str, Any]) -> bool:
        # If data contains the old "api-url" key, turn it into an "instance" key,
        # but only if there is no "instance" key
        try:
            api_url = data.pop("api_url")
        except KeyError:
            pass
        else:
            if "instance" not in data:
                data["instance"] = api_to_dashboard_url(api_url, warn=True)
        return super(UserConfig, self).update_config(data)

    def save(self, config_path: str) -> None:
        """
        Save config to config_path
        """
        self.save_yaml(config_path)

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> Tuple["UserConfig", str]:
        """
        Load the various user configs files to create a UserConfig object:
        - global user configuration file (in the home)
        - local user configuration file (in the repository)

        Returns a UserConfig instance, and the path where updates should be saved
        """

        user_config = UserConfig()
        if config_path:
            data = load_yaml(config_path) or {}
            user_config.update_config(data)
            return user_config, config_path

        for global_config_filename in GLOBAL_CONFIG_FILENAMES:
            global_config_path = get_global_path(global_config_filename)
            global_data = load_yaml(global_config_path)
            if global_data and user_config.update_config(global_data):
                break

        for local_config_path in LOCAL_CONFIG_PATHS:
            local_data = load_yaml(local_config_path)
            if local_data and user_config.update_config(local_data):
                config_path = local_config_path
                break

        if config_path is None:
            config_path = DEFAULT_LOCAL_CONFIG_PATH
        return user_config, config_path

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


def get_auth_config_dir() -> str:
    return user_config_dir(appname="ggshield", appauthor="GitGuardian")


def get_auth_config_filepath() -> str:
    return os.path.join(get_auth_config_dir(), AUTH_CONFIG_FILENAME)


def ensure_path_exists(dir_path: str) -> None:
    Path(dir_path).mkdir(parents=True, exist_ok=True)


class AuthError(click.ClickException):
    """
    Base exception for Auth-related configuration error
    """

    def __init__(self, instance: str, message: str):
        super(AuthError, self).__init__(message)
        self.instance = instance


class UnknownInstanceError(AuthError):
    """
    Raised when the requested instance does not exist
    """

    def __init__(self, instance: str):
        super(UnknownInstanceError, self).__init__(
            instance, f"Unknown instance: '{instance}'"
        )


class AuthExpiredError(AuthError):
    """
    Raised when authentication has expired for the given instance
    """

    def __init__(self, instance: str):
        super(AuthExpiredError, self).__init__(
            instance,
            f"Instance '{instance}' authentication expired, please authenticate again.",
        )


class MissingTokenError(AuthError):
    def __init__(self, instance: str):
        super(MissingTokenError, self).__init__(
            instance, f"No token is saved for this instance: '{instance}'"
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


def get_attr_mapping(
    classes: Iterable[Tuple[Type[YAMLFileConfig], str]]
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
    """
    Top-level config class. Contains an instance of UserConfig and an instance of
    AuthConfig with some magic to make it possible to access their fields directly. For
    example one can do:

    ```
    config = Config()

    # Access config.user_config.exit_zero
    print(config.exit_zero)

    # Access config.auth_config.instances
    print(config.instances)
    ```
    """

    user_config: UserConfig
    auth_config: AuthConfig
    _attr_mapping: Mapping[str, str] = get_attr_mapping(
        [(UserConfig, "user_config"), (AuthConfig, "auth_config")]
    )

    # The instance name, if ggshield is invoked with `--instance`
    _cmdline_instance_name: Optional[str]

    def __init__(self, config_path: Optional[str] = None):
        self.user_config, self._config_path = UserConfig.load(config_path=config_path)
        self.auth_config = AuthConfig.load()
        self._cmdline_instance_name = None

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
        if key[0] == "_" or key in {"user_config", "auth_config"}:
            self.__dict__[key] = value
            return
        subconfig = getattr(self, self._attr_mapping[key])
        setattr(subconfig, key, value)

    def save(self) -> None:
        self.user_config.save(self._config_path)
        self.auth_config.save()

    @property
    def instance_name(self) -> str:
        """
        The instance name (defaulting to URL) of the selected instance
        priority order is:
        - set from the command line (with set_cmdline_instance_name)
        - env var (in auth_config.current_instance)
        - in local user config (in user_config.dashboard_url)
        - in global user config (in user_config.dashboard_url)
        - the default instance
        """
        if self._cmdline_instance_name:
            return self._cmdline_instance_name

        try:
            return os.environ["GITGUARDIAN_INSTANCE"]
        except KeyError:
            pass

        try:
            name = os.environ["GITGUARDIAN_API_URL"]
        except KeyError:
            pass
        else:
            return api_to_dashboard_url(name, warn=True)

        if self.user_config.instance:
            return self.user_config.instance

        return DEFAULT_DASHBOARD_URL

    def set_cmdline_instance_name(self, name: str) -> None:
        """
        Override the current instance name. To be called by commands supporting the
        `--instance` option.
        """
        parsed_url = clean_url(name)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise click.BadParameter(
                "Please provide a valid URL.",
                param_hint="instance",
            )
        self._cmdline_instance_name = f"{parsed_url.scheme}://{parsed_url.netloc}"

    @property
    def api_url(self) -> str:
        """
        The API URL to use to use the API
        It's the API URL from the configured instance
        """
        # TODO change when instance_name can be a name instead of just a URL
        return dashboard_to_api_url(self.instance_name)

    @property
    def dashboard_url(self) -> str:
        """
        The dashboard URL to use to use the dashboard
        It's the dashboard URL from the configured instance
        """
        # TODO change when instance_name can be a name instead of just a URL
        return self.instance_name

    @property
    def api_key(self) -> str:
        """
        The API key to use
        priority order is
        - env var
        - the api key from the selected instance
        """
        try:
            return os.environ["GITGUARDIAN_API_KEY"]
        except KeyError:
            return self.auth_config.get_instance_token(self.instance_name)

    def add_ignored_match(self, *args: Any, **kwargs: Any) -> None:
        return self.user_config.add_ignored_match(*args, **kwargs)
