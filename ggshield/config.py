import os
from typing import Any, Dict, List, NamedTuple, Set

import click
import yaml

from ggshield.config_types import IgnoredMatch


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


class Attribute(NamedTuple):
    name: str
    default: Any


def replace_in_keys(data: Dict, old_char: str, new_char: str) -> None:
    """Replace old_char with new_char in data keys."""
    for key in list(data):
        if old_char in key:
            new_key = key.replace(old_char, new_char)
            data[new_key] = data.pop(key)


class Config:
    all_policies: bool
    api_url: str
    exit_zero: bool
    matches_ignore: List[IgnoredMatch]
    paths_ignore: Set[str]
    show_secrets: bool
    verbose: bool
    allow_self_signed: bool
    max_commits_for_hook: int
    banlisted_detectors: Set[str]
    ignore_default_excludes: bool

    CONFIG_LOCAL = ["./.gitguardian", "./.gitguardian.yml", "./.gitguardian.yaml"]
    CONFIG_GLOBAL = [
        os.path.join(os.path.expanduser("~"), ".gitguardian"),
        os.path.join(os.path.expanduser("~"), ".gitguardian.yml"),
        os.path.join(os.path.expanduser("~"), ".gitguardian.yaml"),
    ]
    DEFAULT_CONFIG_LOCAL = "./.gitguardian.yaml"

    def __init__(self) -> None:
        self.attributes: List[Attribute] = [
            Attribute("all_policies", False),
            Attribute("allow_self_signed", False),
            Attribute("api_url", "https://api.gitguardian.com"),
            Attribute("banlisted_detectors", set()),
            Attribute("exit_zero", False),
            Attribute("matches_ignore", list()),
            Attribute("max_commits_for_hook", 50),
            Attribute("paths_ignore", set()),
            Attribute("show_secrets", False),
            Attribute("verbose", False),
            Attribute("ignore_default_excludes", False),
        ]

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
                if isinstance(getattr(self, key), list):
                    getattr(self, key).extend(item)
                elif isinstance(getattr(self, key), set):
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
        """Loads config files until one succeeds."""
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
                stream = yaml.dump(self.to_dict(), indent=2, default_flow_style=False)
                f.write(stream)

            except Exception as e:
                raise click.ClickException(
                    f"Error while saving config in {config_file}:\n{str(e)}"
                )
        return True

    def add_ignored_match(self, secret: dict) -> None:
        """Add secret to matches_ignore."""

        matches_ignore = [
            match["match"] if isinstance(match, dict) else match
            for match in self.matches_ignore
        ]
        if secret["match"] not in matches_ignore:
            self.matches_ignore.append(secret)
        else:
            for match in self.matches_ignore:
                if (
                    isinstance(match, dict)
                    and match["match"] == secret["match"]
                    and match["name"] == ""
                ):
                    match.update({"name": secret["name"]})
