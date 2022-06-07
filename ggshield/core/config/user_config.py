import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import click

from ggshield.core.config.utils import YAMLFileConfig, get_global_path, load_yaml
from ggshield.core.constants import (
    DEFAULT_DASHBOARD_URL,
    DEFAULT_LOCAL_CONFIG_PATH,
    GLOBAL_CONFIG_FILENAMES,
    LOCAL_CONFIG_PATHS,
)
from ggshield.core.types import IgnoredMatch
from ggshield.core.utils import api_to_dashboard_url, clean_url, dashboard_to_api_url


@dataclass
class UserConfig(YAMLFileConfig):
    """
    Holds all ggshield settings defined by the user in the .gitguardian.yaml files
    (local and global).
    """

    api_url: Optional[str] = None
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

    def update_from_env(self) -> None:
        try:
            self.api_url = os.environ["GITGUARDIAN_API_URL"]
        except KeyError:
            pass
        try:
            self.instance = os.environ["GITGUARDIAN_INSTANCE"]
        except KeyError:
            pass

        if self.api_url:
            self.api_url = clean_url(self.api_url, warn=True).geturl()
        if self.instance:
            self.instance = clean_url(self.instance, warn=True).geturl()

        if self.api_url and not self.instance:
            self.instance = api_to_dashboard_url(self.api_url, warn=True)
        elif self.instance and not self.api_url:
            self.api_url = dashboard_to_api_url(self.instance, warn=True)
        elif not self.api_url and not self.instance:
            self.instance = DEFAULT_DASHBOARD_URL
            self.api_url = dashboard_to_api_url(self.instance, warn=True)

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
            user_config.update_from_env()
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
        user_config.update_from_env()
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
