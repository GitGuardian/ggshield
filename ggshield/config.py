import copy
import json
import os
from typing import Any, Dict, List, NamedTuple

import click
import yaml
from dotenv import load_dotenv
from pygitguardian.models import PolicyBreak

from .git_shell import get_git_root, is_git_dir
from .text_utils import display_error


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])

# max file size to accept
MAX_FILE_SIZE = 1048576

CPU_COUNT = os.cpu_count() or 1


class Attribute(NamedTuple):
    name: str
    default: Any


def replace_in_keys(data: Dict, old_char: str, new_char: str) -> None:
    """ Replace old_char with new_char in data keys. """
    for key in list(data):
        if old_char in key:
            new_key = key.replace(old_char, new_char)
            data[new_key] = data.pop(key)


class Config:
    all_policies: bool
    api_url: str
    exit_zero: bool
    matches_ignore: set
    paths_ignore: set
    show_secrets: bool
    verbose: bool

    CONFIG_LOCAL = ["./.gitguardian", "./.gitguardian.yml", "./.gitguardian.yaml"]
    CONFIG_GLOBAL = [
        os.path.join(os.path.expanduser("~"), ".gitguardian"),
        os.path.join(os.path.expanduser("~"), ".gitguardian.yml"),
        os.path.join(os.path.expanduser("~"), ".gitguardian.yaml"),
    ]
    DEFAULT_CONFIG_LOCAL = "./.gitguardian.yaml"

    attributes: List[Attribute] = [
        Attribute("all_policies", False),
        Attribute("api_url", "https://api.gitguardian.com"),
        Attribute("exit_zero", False),
        Attribute("matches_ignore", set()),
        Attribute("paths_ignore", set()),
        Attribute("show_secrets", False),
        Attribute("verbose", False),
    ]

    def __init__(self) -> None:
        for attr in self.attributes:
            setattr(self, attr.name, attr.default)
        self.load_configs(self.CONFIG_GLOBAL)
        self.load_configs(self.CONFIG_LOCAL)

    def __getattr__(self, name: str) -> Any:
        # Required for dynamic types on mypy
        return object.__getattribute__(self, name)

    def get_attributes_keys(self) -> List:
        return list(
            list(zip(*self.attributes))[0]
        )  # get list of first elements in tuple

    def update_config(self, **kwargs: Any) -> None:
        for key, item in kwargs.items():
            if key in self.get_attributes_keys():
                if isinstance(item, list):
                    getattr(self, key).update(item)
                else:
                    setattr(self, key, item)
            else:
                click.echo("Unrecognized key in config: {}".format(key))

    def load_config(self, filename: str) -> bool:
        if not os.path.isfile(filename):
            return False

        with open(filename, "r") as f:
            try:
                _config = yaml.safe_load(f) or {}
                replace_in_keys(_config, "-", "_")
                self.update_config(**_config)
            except Exception as e:
                raise click.ClickException(
                    f"Parsing error while reading {filename}:\n{str(e)}"
                )

        return True

    def load_configs(self, filenames: List[str]) -> None:
        """ Loads config files until one succeeds. """
        for filename in filenames:
            try:
                if self.load_config(filename):
                    return
            except Exception as exc:
                click.echo(str(exc))

    def to_dict(self) -> Dict[str, Any]:
        _config = {key: getattr(self, key) for key in self.get_attributes_keys()}
        # Convert all sets into more human readable lists
        for key in self.get_attributes_keys():
            value = _config[key]
            if type(value) is set:
                _config[key] = list(value)
        replace_in_keys(_config, "_", "-")
        return _config

    def save(self) -> bool:
        """
        Save config in the first CONFIG_LOCAL file.
        If no local config file, creates a local .gitguardian.yaml
        """
        config_file = self.DEFAULT_CONFIG_LOCAL
        for filename in self.CONFIG_LOCAL:
            if os.path.isfile(filename):
                config_file = filename
                break

        with open(config_file, "w") as f:
            try:
                stream = yaml.dump(self.to_dict(), default_flow_style=False)
                f.write(stream.replace("- ", "  - "))

            except Exception as e:
                raise click.ClickException(
                    f"Error while saving config in {config_file}:\n{str(e)}"
                )
        return True

    def add_ignored_match(self, secret_hash: str) -> None:
        """ Add secret to matches_ignore. """
        current_ignored = self.matches_ignore
        current_ignored.add(secret_hash)


def load_dot_env() -> None:
    """Loads .env file into sys.environ."""
    dont_load_env = os.getenv("GITGUARDIAN_DONT_LOAD_ENV", False)
    dotenv_path = os.getenv("GITGUARDIAN_DOTENV_PATH", None)
    cwd_env = os.path.join(".", ".env")
    if not dont_load_env:
        if dotenv_path and os.path.isfile(dotenv_path):
            load_dotenv(dotenv_path, override=True)
            return
        elif dotenv_path:
            display_error(
                "GITGUARDIAN_DOTENV_LOCATION does not point to a valid .env file"
            )
        if os.path.isfile(cwd_env):
            load_dotenv(cwd_env, override=True)
            return
        if is_git_dir() and os.path.isfile(os.path.join(get_git_root(), ".env")):
            load_dotenv(os.path.join(get_git_root(), ".env"), override=True)
            return


class Cache:

    last_found_secrets: set

    CACHE_FILENAME = "./.cache_ggshield"
    attributes: List[Attribute] = [
        Attribute("last_found_secrets", set()),
    ]

    def __init__(self) -> None:
        self.purge()
        self.load_cache()

    def __getattr__(self, name: str) -> Any:
        # Required for dynamic types on mypy
        return object.__getattribute__(self, name)

    def get_attributes_keys(self) -> List:
        return list(
            list(zip(*self.attributes))[0]
        )  # get list of first elements in tuple

    def create_empty_cache(self) -> None:
        # Creates a new file
        with open(self.CACHE_FILENAME, "w"):
            pass

    def load_cache(self) -> bool:
        if not os.path.isfile(self.CACHE_FILENAME):
            self.create_empty_cache()
            return True

        _cache: dict = {}
        if os.stat(self.CACHE_FILENAME).st_size != 0:
            with open(self.CACHE_FILENAME, "r") as f:
                try:
                    _cache = json.load(f)
                    # Convert back all sets that were serialized as lists
                    for attr in self.attributes:
                        if type(attr.default) is set and attr.name in _cache:
                            _cache[attr.name] = set(_cache[attr.name]) or set()
                except Exception as e:
                    raise click.ClickException(
                        f"Parsing error while reading {self.CACHE_FILENAME}:\n{str(e)}"
                    )
        self.update_cache(**_cache)
        return True

    def update_cache(self, **kwargs: Any) -> None:
        for key, item in kwargs.items():
            if key in self.get_attributes_keys():
                if isinstance(item, list):
                    getattr(self, key).update(item)
                else:
                    setattr(self, key, item)
            else:
                click.echo("Unrecognized key in cache: {}".format(key))

    def to_dict(self) -> Dict[str, Any]:
        _cache = {key: getattr(self, key) for key in self.get_attributes_keys()}
        # Convert all sets into list so they can be json serialized
        for key in self.get_attributes_keys():
            value = _cache[key]
            if type(value) is set:
                _cache[key] = list(value)
        return _cache

    def save(self) -> bool:
        if not os.path.isfile(self.CACHE_FILENAME):
            return False

        with open(self.CACHE_FILENAME, "w") as f:
            try:
                json.dump(self.to_dict(), f)

            except Exception as e:
                raise click.ClickException(
                    f"Error while saving cache in {self.CACHE_FILENAME}:\n{str(e)}"
                )
        return True

    def purge(self) -> None:
        for attr in self.attributes:
            # Deep copy to avoid mutating the default value
            default = copy.copy(attr.default)
            setattr(self, attr.name, default)

    def add_found_secret(self, hash: str) -> None:
        self.last_found_secrets.add(hash)

    def add_found_policy_break(self, policy_break: PolicyBreak) -> None:
        if policy_break.policy.lower() == "secrets detection":
            for match in policy_break.matches:
                self.add_found_secret(match.match)
