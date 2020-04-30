import os
from typing import Any, Dict

import click
import yaml


# The order is important, we look at the first existing file
CONFIG_LOCAL = ["./.gitguardian", "./.gitguardian.yml", "./.gitguardian.yaml"]
CONFIG_GLOBAL = [
    "{}/.gitguardian".format(os.path.expanduser("~")),
    "{}/.gitguardian.yml".format(os.path.expanduser("~")),
    "{}/.gitguardian.yaml".format(os.path.expanduser("~")),
]


def load_config() -> Dict:
    """ Return configuration. """
    config = {}
    _init_config(config)

    for filename in CONFIG_LOCAL:
        if os.path.isfile(filename):
            with open(filename, "r") as f:
                try:
                    _config = yaml.load(f, Loader=yaml.SafeLoader)
                    _load_config(config, _config)
                except yaml.scanner.ScannerError:
                    raise click.ClickException(
                        "Parsing error while opening {}".format(filename)
                    )

            break

    for filename in CONFIG_GLOBAL:
        if os.path.isfile(filename):
            with open(filename, "r") as f:
                try:
                    _config = yaml.load(f, Loader=yaml.SafeLoader)
                    _load_config(config, _config)
                except yaml.scanner.ScannerError:
                    raise click.ClickException(
                        "Parsing error while opening {}".format(filename)
                    )

            break

    return config


def _init_config(config: Dict[str, Any]):
    """ Initiate all the options. """
    config["ignored_matches"] = set()
    config["exclude"] = ""


def _load_config(config: Dict[str, Any], _config: Dict[str, Any]):
    """ Load all the options (update config with _config) """
    load_exclude(config, _config)
    load_ignored_matches(config, _config)


def load_ignored_matches(config: Dict[str, Any], _config: Dict[str, Any]):
    """ Load ignored matches. """
    if "ignored_matches" in _config:
        config["ignored_matches"].update(_config["ignored_matches"])


def load_exclude(config: Dict[str, Any], _config: Dict[str, Any]):
    """ Load list of ignored files. """
    if "exclude" in _config:
        config["exclude"] = _config["exclude"]
