import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import click
import marshmallow_dataclass
from marshmallow import ValidationError

from ggshield.core.config.errors import ParseError
from ggshield.core.config.utils import (
    get_global_path,
    load_yaml,
    save_yaml,
    update_from_other_instance,
)
from ggshield.core.constants import (
    DEFAULT_LOCAL_CONFIG_PATH,
    GLOBAL_CONFIG_FILENAMES,
    LOCAL_CONFIG_PATHS,
)
from ggshield.core.types import IgnoredMatch
from ggshield.core.utils import api_to_dashboard_url


@dataclass
class UserConfig:
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

    def save(self, config_path: str) -> None:
        """
        Save config to config_path
        """
        schema = UserConfigSchema()
        save_yaml(schema.dump(self), config_path)

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
            user_config._update_from_file(config_path)
            return user_config, config_path

        for global_config_filename in GLOBAL_CONFIG_FILENAMES:
            global_config_path = get_global_path(global_config_filename)
            if os.path.exists(global_config_path):
                user_config._update_from_file(global_config_path)
                break

        for local_config_path in LOCAL_CONFIG_PATHS:
            if os.path.exists(local_config_path):
                user_config._update_from_file(local_config_path)
                config_path = local_config_path
                break

        if config_path is None:
            config_path = DEFAULT_LOCAL_CONFIG_PATH
        return user_config, config_path

    def _update_from_file(self, config_path: str) -> None:
        data = load_yaml(config_path) or {}

        # If data contains the old "api-url" key, turn it into an "instance" key,
        # but only if there is no "instance" key
        try:
            api_url = data.pop("api_url")
        except KeyError:
            pass
        else:
            if "instance" not in data:
                data["instance"] = api_to_dashboard_url(api_url, warn=True)
        schema = UserConfigSchema()
        try:
            obj = schema.load(data)
        except ValidationError as exc:
            raise ParseError(f"Error in {config_path}:\n{str(exc)}")

        update_from_other_instance(self, obj)

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


UserConfigSchema = marshmallow_dataclass.class_schema(UserConfig)
