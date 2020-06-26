import os
from typing import Any, Dict, List, NamedTuple

import click
import yaml


# The order is important, we look at the first existing file


class Config:
    class Attribute(NamedTuple):
        name: str
        default: Any

    CONFIG_LOCAL = ["./.gitguardian", "./.gitguardian.yml", "./.gitguardian.yaml"]
    CONFIG_GLOBAL = [
        os.path.join(os.path.expanduser("~"), ".gitguardian"),
        os.path.join(os.path.expanduser("~"), ".gitguardian.yml"),
        os.path.join(os.path.expanduser("~"), ".gitguardian.yaml"),
    ]

    attributes: List[Attribute] = [
        Attribute("all_policies", False),
        Attribute("api_url", "https://api.gitguardian.com"),
        Attribute("exit_zero", False),
        Attribute("matches_ignore", set()),
        Attribute("paths_ignore", set()),
        Attribute("show_secrets", False),
        Attribute("verbose", False),
    ]

    def __init__(self):
        for attr in self.attributes:
            setattr(self, attr.name, attr.default)
        self.load_configs(self.CONFIG_GLOBAL)
        self.load_configs(self.CONFIG_LOCAL)

    def update_config(
        self, **kwargs,
    ):
        for key, item in kwargs.items():
            if key in list(
                list(zip(*self.attributes))[0]
            ):  # get list of first elements in tuple
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
                _config = yaml.safe_load(f)
                self.clean_keys(_config)
                self.update_config(**_config)
            except yaml.scanner.ScannerError:
                raise click.ClickException(
                    "Parsing error while opening {}".format(filename)
                )

        return True

    def load_configs(self, filenames: List[str]):
        """
        load_configs loads config files until one succeeds
        """
        for filename in filenames:
            try:
                if self.load_config(filename):
                    return
            except Exception as exc:
                click.echo(str(exc))

    @staticmethod
    def clean_keys(yaml_config: Dict):
        for key in list(yaml_config):
            if "-" in key:
                new_key = key.replace("-", "_")
                yaml_config[new_key] = yaml_config.pop(key)
