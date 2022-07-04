import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import click
import marshmallow_dataclass
from marshmallow import ValidationError

from ggshield.core.config.errors import ParseError, format_validation_error
from ggshield.core.config.utils import (
    get_global_path,
    load_yaml,
    remove_common_dict_items,
    save_yaml,
    update_from_other_instance,
)
from ggshield.core.constants import (
    DEFAULT_LOCAL_CONFIG_PATH,
    GLOBAL_CONFIG_FILENAMES,
    LOCAL_CONFIG_PATHS,
)
from ggshield.core.types import FilteredConfig, IgnoredMatch, IgnoredMatchSchema
from ggshield.core.utils import api_to_dashboard_url
from ggshield.iac.utils import POLICY_ID_PATTERN, validate_policy_id


logger = logging.getLogger(__name__)
CURRENT_CONFIG_VERSION = 2


@marshmallow_dataclass.dataclass
class SecretConfig(FilteredConfig):
    """
    Holds all user-defined secret-specific settings
    """

    show_secrets: bool = False
    ignored_detectors: Set[str] = field(default_factory=set)
    ignored_matches: List[IgnoredMatch] = field(default_factory=list)
    ignored_paths: Set[str] = field(default_factory=set)

    def add_ignored_match(self, secret: IgnoredMatch) -> None:
        """
        Add secret to ignored_matches.
        """
        for match in self.ignored_matches:
            if match.match == secret.match:
                # take the opportunity to name the ignored match
                if not match.name:
                    match.name = secret.name
                return
        self.ignored_matches.append(secret)


def validate_policy_ids(values: Iterable[str]) -> None:
    invalid_excluded_policies = [
        policy_id for policy_id in values if not validate_policy_id(policy_id)
    ]
    if len(invalid_excluded_policies) > 0:
        raise ValidationError(
            f"The policies {invalid_excluded_policies} do not match the pattern '{POLICY_ID_PATTERN.pattern}'"
        )


@marshmallow_dataclass.dataclass
class IaCConfig(FilteredConfig):
    """
    Holds the iac config as defined .gitguardian.yaml files
    (local and global).
    """

    ignored_paths: Set[str] = field(default_factory=set)
    ignored_policies: Set[str] = field(
        default_factory=set, metadata={"validate": validate_policy_ids}
    )
    minimum_severity: str = "LOW"


@marshmallow_dataclass.dataclass
class UserConfig(FilteredConfig):
    """
    Holds all ggshield settings defined by the user in the .gitguardian.yaml files
    (local and global).
    """

    iac: IaCConfig = field(default_factory=IaCConfig)
    instance: Optional[str] = None
    exit_zero: bool = False
    verbose: bool = False
    allow_self_signed: bool = False
    max_commits_for_hook: int = 50
    secret: SecretConfig = field(default_factory=SecretConfig)
    debug: bool = False

    # If we hit any deprecated syntax when loading a configuration file, we do not
    # display them directly, otherwise the messages would also be shown when running
    # `ggshield config migrate`, which would be odd.
    # Instead, we store them in this list and a result_callback() function displays
    # them when we quit. When `config migrate` runs, it clears this list, so nothing
    # gets displayed.
    deprecation_messages: List[str] = field(default_factory=list)

    def save(self, config_path: str) -> None:
        """
        Save config to config_path
        """
        schema = UserConfigSchema(exclude=("deprecation_messages",))
        dct = schema.dump(self)
        default_dct = schema.dump(schema.load({}))

        dct = remove_common_dict_items(dct, default_dct)

        dct["version"] = CURRENT_CONFIG_VERSION

        save_yaml(dct, config_path)

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
            logger.debug("Loading custom config from %s", config_path)
            user_config._update_from_file(config_path)
            return user_config, config_path

        for global_config_filename in GLOBAL_CONFIG_FILENAMES:
            global_config_path = get_global_path(global_config_filename)
            if os.path.exists(global_config_path):
                user_config._update_from_file(global_config_path)
                logger.debug("Loaded global config from %s", global_config_path)
                break
        else:
            logger.debug("No global config")

        for local_config_path in LOCAL_CONFIG_PATHS:
            if os.path.exists(local_config_path):
                user_config._update_from_file(local_config_path)
                config_path = local_config_path
                logger.debug("Loaded local config from %s", local_config_path)
                break
        else:
            logger.debug("No local config")

        if config_path is None:
            config_path = DEFAULT_LOCAL_CONFIG_PATH
        return user_config, config_path

    def _update_from_file(self, config_path: str) -> None:
        data = load_yaml(config_path) or {"version": CURRENT_CONFIG_VERSION}
        config_version = data.pop("version", 1)

        try:
            if config_version == 2:
                obj = UserConfigSchema().load(data)
            elif config_version == 1:
                self.deprecation_messages.append(
                    f"{config_path} uses a deprecated configuration file format."
                    " Run `ggshield config migrate` to migrate it to the latest version."
                )
                obj = UserV1Config.load_v1(data)
            else:
                raise click.ClickException(
                    f"Don't know how to load config version {config_version}"
                )
        except ValidationError as exc:
            message = format_validation_error(exc)
            raise ParseError(f"Error in {config_path}:\n{message}") from exc

        update_from_other_instance(self, obj)


UserConfigSchema = marshmallow_dataclass.class_schema(UserConfig)


@dataclass
class UserV1Config:
    """
    Can load a v1 .gitguardian.yaml file
    """

    instance: Optional[str] = None
    all_policies: bool = False
    exit_zero: bool = False
    matches_ignore: List[Dict[str, Optional[str]]] = field(default_factory=list)
    paths_ignore: Set[str] = field(default_factory=set)
    verbose: bool = False
    allow_self_signed: bool = False
    max_commits_for_hook: int = 50
    ignore_default_excludes: bool = False
    show_secrets: bool = False
    banlisted_detectors: Set[str] = field(default_factory=set)

    @staticmethod
    def load_v1(data: Dict[str, Any]) -> UserConfig:
        """
        Takes a dict representing a v1 .gitguardian.yaml and returns a v2 config object
        """
        # If data contains the old "api-url" key, turn it into an "instance" key,
        # but only if there is no "instance" key
        try:
            api_url = data.pop("api_url")
        except KeyError:
            pass
        else:
            if "instance" not in data:
                data["instance"] = api_to_dashboard_url(api_url, warn=True)

        UserV1Config.matches_ignore_to_dict(data)

        v1config = UserV1ConfigSchema().load(data)

        deprecation_messages = []

        if v1config.all_policies:
            deprecation_messages.append(
                "The `all_policies` option has been deprecated and is now ignored."
            )

        if v1config.ignore_default_excludes:
            deprecation_messages.append(
                "The `ignore_default_exclude` option has been deprecated and is now ignored."
            )

        ignored_match_schema = IgnoredMatchSchema()
        ignored_matches = [
            ignored_match_schema.load(secret) for secret in v1config.matches_ignore
        ]
        secret = SecretConfig(
            show_secrets=v1config.show_secrets,
            ignored_detectors=v1config.banlisted_detectors,
            ignored_matches=ignored_matches,
            ignored_paths=v1config.paths_ignore,
        )

        return UserConfig(
            instance=v1config.instance,
            exit_zero=v1config.exit_zero,
            verbose=v1config.verbose,
            allow_self_signed=v1config.allow_self_signed,
            max_commits_for_hook=v1config.max_commits_for_hook,
            secret=secret,
            deprecation_messages=deprecation_messages,
        )

    @staticmethod
    def matches_ignore_to_dict(data: Dict[str, Any]) -> None:
        """
        v1 config format allowed to use just a hash of the secret for matches_ignore
        field v2 does not. This function converts the hash-only matches.
        """
        matches_ignore = data.get("matches_ignore")
        if not matches_ignore:
            return

        for idx, match in enumerate(matches_ignore):
            if isinstance(match, str):
                matches_ignore[idx] = {"name": "", "match": match}


UserV1ConfigSchema = marshmallow_dataclass.class_schema(UserV1Config)
