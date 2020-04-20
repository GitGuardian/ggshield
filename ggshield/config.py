import os
import sys
from typing import Dict

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
                    _config = yaml.load(f, Loader=yaml.FullLoader)
                    _load_config(config, _config)
                except yaml.scanner.ScannerError:
                    raise click.ClickException(
                        "Parsing error while opening {}".format(filename)
                    )
                    sys.exit(1)

            break

    for filename in CONFIG_GLOBAL:
        if os.path.isfile(filename):
            with open(filename, "r") as f:
                try:
                    _config = yaml.load(f, Loader=yaml.FullLoader)
                    _load_config(config, _config)
                except yaml.scanner.ScannerError:
                    raise click.ClickException(
                        "Parsing error while opening {}".format(filename)
                    )
                    sys.exit(1)

            break

    return config


def _init_config(config: Dict):
    """ Initiate all the options. """
    config["blacklist"] = set()
    config["ignore"] = {"filename": set(), "extension": set()}


def _load_config(config: Dict, _config: Dict):
    """ Load all the options (update config with _config) """
    load_blacklist(config, _config)
    load_ignore(config, _config)


def load_blacklist(config: Dict, _config: Dict):
    """ Load blacklist. """
    if "detectors" in _config and "blacklist" in _config["detectors"]:
        config["blacklist"].update(_config["detectors"]["blacklist"])


def load_ignore(config: Dict, _config: Dict):
    """ Load list of ignored files. """
    if "ignore" in _config:
        if "filename" in _config["ignore"]:
            config["ignore"]["filename"].update(_config["ignore"]["filename"])
        if "extension" in _config["ignore"]:
            config["ignore"]["extension"].update(_config["ignore"]["extension"])
