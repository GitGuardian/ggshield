import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import marshmallow_dataclass
from marshmallow import ValidationError, post_load
from pygitguardian.models import FromDictMixin

from ggshield.core.config.utils import (
    find_global_config_path,
    find_local_config_path,
    load_yaml_dict,
    remove_common_dict_items,
    replace_in_keys,
    save_yaml_dict,
    update_from_other_instance,
)
from ggshield.core.constants import DEFAULT_LOCAL_CONFIG_PATH
from ggshield.core.errors import ParseError, UnexpectedError, format_validation_error
from ggshield.core.text_utils import display_warning
from ggshield.core.types import FilteredConfig, IgnoredMatch
from ggshield.core.utils import api_to_dashboard_url
from ggshield.iac.policy_id import POLICY_ID_PATTERN, validate_policy_id
from ggshield.sca.vuln_identifier import GHSA_ID_PATTERN, is_ghsa_valid


logger = logging.getLogger(__name__)
CURRENT_CONFIG_VERSION = 2

_IGNORE_KNOWN_SECRETS_KEY = "ignore-known-secrets"


@marshmallow_dataclass.dataclass
class SecretConfig(FilteredConfig):
    """
    Holds all user-defined secret-specific settings
    """

    show_secrets: bool = False
    ignored_detectors: Set[str] = field(default_factory=set)
    ignored_matches: List[IgnoredMatch] = field(default_factory=list)
    ignored_paths: Set[str] = field(default_factory=set)
    ignore_known_secrets: bool = False

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


def validate_vuln_identifier(value: str):
    if not is_ghsa_valid(value):
        raise ValidationError(
            f"The given GHSA id '{value}' do not match the pattern '{GHSA_ID_PATTERN.pattern}'"
        )


@marshmallow_dataclass.dataclass
class SCAIgnoredVulnerability(FilteredConfig):
    """
    A model of an ignored vulnerability for SCA. This allows to ignore all occurrences
    of a given vulnerability in a given dependency file.
    - identifier: identifier (currently: GHSA id) of the vulnerability to ignore
    - path: the path to the file in which ignore the vulnerability
    - comment: The ignored reason
    - until: A datetime until which the vulnerability is ignored
    """

    identifier: str = field(metadata={"validate": validate_vuln_identifier})
    path: str
    comment: Optional[str]
    until: Optional[datetime]

    @post_load
    def datetime_to_utc(self, data, **kwargs):
        if data["until"] is not None:
            data["until"] = data["until"].astimezone(timezone.utc)
        return data


@marshmallow_dataclass.dataclass
class SCAConfig(FilteredConfig):
    """
    Holds the sca config as defined .gitguardian.yaml files
    (local and global).
    """

    ignored_paths: Set[str] = field(default_factory=set)
    minimum_severity: str = "LOW"
    ignored_vulnerabilities: List[SCAIgnoredVulnerability] = field(default_factory=list)

    @post_load
    def validate_ignored_vulns(self, data, **kwargs):
        valid_vulnerabilities = []
        for vuln in data["ignored_vulnerabilities"]:
            if vuln.until is None or vuln.until > datetime.now(tz=timezone.utc):
                valid_vulnerabilities.append(vuln)
            else:
                display_warning(
                    f"Vulnerability {vuln.identifier} in {vuln.path} has an expired 'until'"
                    f"date ({vuln.until}), please udpate your configuration file."
                )
        data["ignored_vulnerabilities"] = valid_vulnerabilities
        return data


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
    sca: SCAConfig = field(default_factory=SCAConfig)
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
        dct = self.to_dict()
        default_dct = UserConfig.from_dict({}).to_dict()

        dct = remove_common_dict_items(dct, default_dct)

        dct["version"] = CURRENT_CONFIG_VERSION

        replace_in_keys(dct, old_char="_", new_char="-")
        save_yaml_dict(dct, config_path)

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

        global_config_path = find_global_config_path()
        if global_config_path:
            user_config._update_from_file(global_config_path)
            logger.debug("Loaded global config from %s", global_config_path)
        else:
            logger.debug("No global config")

        local_config_path = find_local_config_path()
        if local_config_path:
            user_config._update_from_file(local_config_path)
            config_path = local_config_path
            logger.debug("Loaded local config from %s", local_config_path)
        else:
            logger.debug("No local config")

        if config_path is None:
            config_path = DEFAULT_LOCAL_CONFIG_PATH
        return user_config, config_path

    def _update_from_file(self, config_path: str) -> None:
        try:
            data = load_yaml_dict(config_path) or {"version": CURRENT_CONFIG_VERSION}
            config_version = data.pop("version", 1)
            if config_version == 2:
                _fix_ignore_known_secrets(data)
                obj = UserConfig.from_dict(data)
            elif config_version == 1:
                replace_in_keys(data, old_char="-", new_char="_")
                self.deprecation_messages.append(
                    f"{config_path} uses a deprecated configuration file format."
                    " Run `ggshield config migrate` to migrate it to the latest version."
                )
                obj = UserV1Config.load_v1(data)
            else:
                raise UnexpectedError(
                    f"Don't know how to load config version {config_version}"
                )
        except ValidationError as exc:
            message = format_validation_error(exc)
            raise ParseError(message) from exc
        except ValueError as exc:
            raise ParseError(str(exc)) from exc

        update_from_other_instance(self, obj)


UserConfig.SCHEMA = marshmallow_dataclass.class_schema(UserConfig)(
    exclude=("deprecation_messages",)
)


def _fix_ignore_known_secrets(data: Dict[str, Any]) -> None:
    """Fix a mistake done when implementing ignore-known-secrets: since this is a secret
    specific key, it should have been stored in the "secret" mapping, not in the root
    one"""

    underscore_key = _IGNORE_KNOWN_SECRETS_KEY.replace("-", "_")

    for key in _IGNORE_KNOWN_SECRETS_KEY, underscore_key:
        value = data.pop(key, None)
        if value is not None:
            break
    else:
        # No key to fix
        return

    secret_dct = data.setdefault("secret", {})
    if _IGNORE_KNOWN_SECRETS_KEY in secret_dct or underscore_key in secret_dct:
        # Do not override if it's already there
        return
    secret_dct[_IGNORE_KNOWN_SECRETS_KEY] = value


@dataclass
class UserV1Config(FromDictMixin):
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

        v1config = UserV1Config.from_dict(data)

        deprecation_messages = []

        if v1config.all_policies:
            deprecation_messages.append(
                "The `all_policies` option has been deprecated and is now ignored."
            )

        if v1config.ignore_default_excludes:
            deprecation_messages.append(
                "The `ignore_default_exclude` option has been deprecated and is now ignored."
            )

        ignored_matches = [
            IgnoredMatch.from_dict(secret) for secret in v1config.matches_ignore
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


UserV1Config.SCHEMA = marshmallow_dataclass.class_schema(UserV1Config)()
