import logging
import os
import re
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Set, Tuple

import click

from ggshield.core.config.auth_config import AuthConfig
from ggshield.core.config.user_config import UserConfig
from ggshield.core.config.utils import remove_url_trailing_slash
from ggshield.core.constants import DEFAULT_HMSL_URL, DEFAULT_INSTANCE_URL
from ggshield.core.url_utils import (
    api_to_dashboard_url,
    clean_url,
    dashboard_to_api_url,
    validate_instance_url,
)


class ConfigSource(Enum):
    """
    Enum of the different sources of configuration
    where an API key or instance URL can come from
    """

    CMD_OPTION = "command line option"
    DOTENV = ".env file"
    ENV_VAR = "environment variable"
    USER_CONFIG = "user config"
    DEFAULT = "default"


logger = logging.getLogger(__name__)


class Config:
    """
    Top-level config class. Contains an instance of UserConfig and an instance of
    AuthConfig.
    """

    __slots__ = [
        "user_config",
        "auth_config",
        "_cmdline_instance_name",
        "_config_path",
        "_dotenv_vars",
    ]

    user_config: UserConfig
    auth_config: AuthConfig

    # The instance name, if ggshield is invoked with `--instance`
    _cmdline_instance_name: Optional[str]

    _config_path: Path

    # This environment variable helps us knowing whether environment variables
    # were set by the dotenv file or not
    # It is used in the `api-status` command to return the API key and instance sources
    _dotenv_vars: Set[str]

    def __init__(self, config_path: Optional[Path] = None):
        self.user_config, self._config_path = UserConfig.load(config_path=config_path)
        self.auth_config = AuthConfig.load()
        self._cmdline_instance_name = None
        self._dotenv_vars = set()

    def save(self) -> None:
        self.user_config.save(self._config_path)
        self.auth_config.save()

    @property
    def config_path(self) -> Path:
        return self._config_path

    @property
    def instance_name(self) -> str:
        return self.get_instance_name_and_source()[0]

    def get_instance_name_and_source(self) -> Tuple[str, ConfigSource]:
        """
        Return the instance name and source of the selected instance.

        The instance name (defaulting to URL) of the selected instance
        priority order is:
        - set from the command line (by setting cmdline_instance_name)
          - in case the user set the api url instead of dashboard url, we replace it
        - GITGUARDIAN_INSTANCE env var
        - GITGUARDIAN_API_URL env var
        - in local user config (in user_config.dashboard_url)
        - in global user config (in user_config.dashboard_url)
        - the default instance
        """
        if self._cmdline_instance_name:
            if re.match(
                r"^https:\/\/api(\.[a-z0-9]+)?\.gitguardian\.com",
                self._cmdline_instance_name,
            ) or re.match(r"/exposed/?$", self._cmdline_instance_name):
                return (
                    api_to_dashboard_url(self._cmdline_instance_name),
                    ConfigSource.CMD_OPTION,
                )
            return self._cmdline_instance_name, ConfigSource.CMD_OPTION

        try:
            url = os.environ["GITGUARDIAN_INSTANCE"]
            logger.debug("Using instance URL from $GITGUARDIAN_INSTANCE")
        except KeyError:
            pass
        else:
            validate_instance_url(url)
            source = (
                ConfigSource.DOTENV
                if "GITGUARDIAN_INSTANCE" in self._dotenv_vars
                else ConfigSource.ENV_VAR
            )
            return remove_url_trailing_slash(url), source

        try:
            name = os.environ["GITGUARDIAN_API_URL"]
            logger.debug("Using API URL from $GITGUARDIAN_API_URL")
        except KeyError:
            pass
        else:
            source = (
                ConfigSource.DOTENV
                if "GITGUARDIAN_API_URL" in self._dotenv_vars
                else ConfigSource.ENV_VAR
            )
            return api_to_dashboard_url(name, warn=True), source

        if self.user_config.instance:
            return self.user_config.instance, ConfigSource.USER_CONFIG

        return DEFAULT_INSTANCE_URL, ConfigSource.DEFAULT

    @property
    def cmdline_instance_name(self) -> Optional[str]:
        return self._cmdline_instance_name

    @cmdline_instance_name.setter
    def cmdline_instance_name(self, name: str) -> None:
        """
        Override the current instance name. To be called by commands supporting the
        `--instance` option.
        """
        parsed_url = clean_url(name)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise click.BadParameter(
                "Please provide a valid URL.",
                param_hint="instance",
            )
        self._cmdline_instance_name = f"{parsed_url.scheme}://{parsed_url.netloc}"

    @property
    def api_url(self) -> str:
        """
        The API URL to use the API
        It's the API URL from the configured instance
        """
        # TODO change when instance_name can be a name instead of just a URL
        return dashboard_to_api_url(self.instance_name)

    @property
    def dashboard_url(self) -> str:
        """
        The dashboard URL to use the dashboard
        It's the dashboard URL from the configured instance
        """
        # TODO change when instance_name can be a name instead of just a URL
        return self.instance_name

    @property
    def api_key(self) -> str:
        return self.get_api_key_and_source()[0]

    def get_api_key_and_source(self) -> Tuple[str, ConfigSource]:
        """
        Return the selected API key and its source

        The API key to use
        priority order is
        - env var
        - the api key from the selected instance
        """
        try:
            key = os.environ["GITGUARDIAN_API_KEY"]
            logger.debug("Using API key from $GITGUARDIAN_API_KEY")
            source = (
                ConfigSource.DOTENV
                if "GITGUARDIAN_API_KEY" in self._dotenv_vars
                else ConfigSource.ENV_VAR
            )
        except KeyError:
            key = self.auth_config.get_instance_token(self.instance_name)
            source = ConfigSource.USER_CONFIG
        return key, source

    def add_ignored_match(self, *args: Any, **kwargs: Any) -> None:
        return self.user_config.secret.add_ignored_match(*args, **kwargs)

    @property
    def saas_api_url(self) -> str:
        """
        The GIM SaaS instance used to get JWT tokens.
        This can be overridden with the GITGUARDIAN_SAAS_URL environment variable.
        If the HMSL URL is different from the default, we derive the SaaS API from it.
        Otherwise the SaaS API URL is actually the one derived from the dashboard
        """
        if self.hmsl_url != DEFAULT_HMSL_URL and "api" in self.hmsl_url:
            default_value = self.hmsl_url.replace("hasmysecretleaked", "gitguardian")
        else:
            default_value = self.api_url

        return os.environ.get(
            "GITGUARDIAN_SAAS_URL",
            default_value,
        )

    @property
    def saas_api_key(self) -> str:
        """
        The API key associated with the SaaS GIM instance.
        For testing purposes, it can be overridden with the
        GITGUARDIAN_SAAS_API_KEY environment variable.
        """
        try:
            key = os.environ["GITGUARDIAN_SAAS_API_KEY"]
            logger.debug("Using API key from $GITGUARDIAN_SAAS_API_KEY")
        except KeyError:
            pass
        else:
            return key
        logger.debug("Using API key for SaaS instance from config")
        return self.api_key

    # Properties for HasMySecretLeaked
    # We can't rely on the instance selected by the user,
    # as JWT creation is only available in SaaS.
    @property
    def hmsl_url(self) -> str:
        """
        The url of the HasMySecretLeaked service
        """
        try:
            url = os.environ["GITGUARDIAN_HMSL_URL"]
            logger.debug("Using HasMySecretLeaked URL from $GITGUARDIAN_HMSL_URL")
        except KeyError:
            url = DEFAULT_HMSL_URL
            logger.debug("Using default HasMySecretLeaked URL")
        return remove_url_trailing_slash(url)

    @property
    def hmsl_audience(self) -> str:
        """
        The audience of our JWT tokens for HasMySecretLeaked.
        """
        try:
            audience = os.environ["GITGUARDIAN_HMSL_AUDIENCE"]
            logger.debug("Using audience from $GITGUARDIAN_HMSL_AUDIENCE")
        except KeyError:
            audience = self.hmsl_url
            logger.debug("Using HasMySecretLeaked URL as audience")
        return audience
