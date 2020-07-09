import os
from typing import Any, Dict, List, NamedTuple

import click
import yaml
from dotenv import load_dotenv

from .git_shell import get_git_root, is_git_dir
from .text_utils import display_error


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])
# max file size to accept
MAX_FILE_SIZE = 1048576

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

    def load_configs(self, filenames: List[str]) -> None:
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
    def clean_keys(yaml_config: Dict) -> None:
        for key in list(yaml_config):
            if "-" in key:
                new_key = key.replace("-", "_")
                yaml_config[new_key] = yaml_config.pop(key)


def load_dot_env():
    """Loads .env file into sys.environ."""
    dont_load_env = os.getenv("GITGUARDIAN_DONT_LOAD_ENV")
    dotenv_path = os.getenv("GITGUARDIAN_DOTENV_PATH")
    cwd_env = os.path.join(".", ".env")
    if not dont_load_env:
        if dotenv_path and os.path.isfile(dotenv_path):
            load_dotenv(dotenv_path, override=True)
            return
        else:
            display_error(
                "GITGUARDIAN_DOTENV_LOCATION does not point to a valid .env file"
            )
        if os.path.isfile(cwd_env):
            load_dotenv(cwd_env, override=True)
            return
        if is_git_dir() and os.path.isfile(os.path.join(get_git_root(), ".env")):
            load_dotenv(os.path.join(get_git_root(), ".env"), override=True)
            return
