import os
from typing import Dict, List

import click
import yaml


# The order is important, we look at the first existing file


class Config:
    CONFIG_LOCAL = ["./.gitguardian", "./.gitguardian.yml", "./.gitguardian.yaml"]
    CONFIG_GLOBAL = [
        os.path.join(os.path.expanduser("~"), ".gitguardian"),
        os.path.join(os.path.expanduser("~"), ".gitguardian.yml"),
        os.path.join(os.path.expanduser("~"), ".gitguardian.yaml"),
    ]

    def __init__(self):
        self.matches_ignore = set()
        self.paths_ignore = set()
        self.verbose = False
        self.show_secrets = False
        self.all_policies = False
        self.load_configs(self.CONFIG_GLOBAL)
        self.load_configs(self.CONFIG_LOCAL)

    def update_config(
        self,
        matches_ignore: List[str] = [],
        paths_ignore: List[str] = [],
        show_secrets: bool = None,
        all_policies: bool = None,
        verbose: bool = None,
        **kwargs,
    ):
        if matches_ignore is not None:
            self.matches_ignore.update(matches_ignore)
        if paths_ignore is not None:
            self.paths_ignore.update(paths_ignore)
        if verbose is not None:
            self.verbose = verbose
        if show_secrets is not None:
            self.show_secrets = show_secrets
        if all_policies:
            self.all_policies = all_policies

        for key in kwargs:
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
