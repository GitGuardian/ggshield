import logging
import os
from typing import Any, Mapping, Optional

import click

from ggshield.core.config.auth_config import AuthConfig
from ggshield.core.config.user_config import UserConfig
from ggshield.core.config.utils import get_attr_mapping, remove_url_trailing_slash
from ggshield.core.constants import DEFAULT_HMSL_URL, DEFAULT_INSTANCE_URL
from ggshield.core.utils import api_to_dashboard_url, clean_url, dashboard_to_api_url


logger = logging.getLogger(__name__)


class Config:
    """
    Top-level config class. Contains an instance of UserConfig and an instance of
    AuthConfig with some magic to make it possible to access their fields directly. For
    example one can do:

    ```
    config = Config()

    # Access config.user_config.exit_zero
    print(config.exit_zero)

    # Access config.auth_config.instances
    print(config.instances)
    ```
    """

    user_config: UserConfig
    auth_config: AuthConfig
    _attr_mapping: Mapping[str, str] = get_attr_mapping(
        [(UserConfig, "user_config"), (AuthConfig, "auth_config")]
    )

    # The instance name, if ggshield is invoked with `--instance`
    _cmdline_instance_name: Optional[str]

    def __init__(self, config_path: Optional[str] = None):
        self.user_config, self._config_path = UserConfig.load(config_path=config_path)
        self.auth_config = AuthConfig.load()
        self._cmdline_instance_name = None

    def __getattr__(self, name: str) -> Any:
        try:
            subconfig_name = self._attr_mapping[name]
        except KeyError:
            raise AttributeError(
                f"'{self.__class__.__name__}' has no attribute '{name}'"
            )
        subconfig = getattr(self, subconfig_name)
        return getattr(subconfig, name)

    def __setattr__(self, key: str, value: Any) -> None:
        if key[0] == "_" or key in {"user_config", "auth_config"}:
            self.__dict__[key] = value
            return
        subconfig = getattr(self, self._attr_mapping[key])
        setattr(subconfig, key, value)

    def save(self) -> None:
        self.user_config.save(self._config_path)
        self.auth_config.save()

    @property
    def config_path(self) -> str:
        return self._config_path

    @property
    def instance_name(self) -> str:
        """
        The instance name (defaulting to URL) of the selected instance
        priority order is:
        - set from the command line (with set_cmdline_instance_name)
        - env var (in auth_config.current_instance)
        - in local user config (in user_config.dashboard_url)
        - in global user config (in user_config.dashboard_url)
        - the default instance
        """
        if self._cmdline_instance_name:
            return self._cmdline_instance_name

        try:
            url = os.environ["GITGUARDIAN_INSTANCE"]
            logger.debug("Using instance URL from $GITGUARDIAN_INSTANCE")
        except KeyError:
            pass
        else:
            return remove_url_trailing_slash(url)

        try:
            name = os.environ["GITGUARDIAN_API_URL"]
            logger.debug("Using API URL from $GITGUARDIAN_API_URL")
        except KeyError:
            pass
        else:
            return api_to_dashboard_url(name, warn=True)

        if self.user_config.instance:
            return self.user_config.instance

        return DEFAULT_INSTANCE_URL

    def set_cmdline_instance_name(self, name: str) -> None:
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
        The API URL to use to use the API
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
        """
        The API key to use
        priority order is
        - env var
        - the api key from the selected instance
        """
        try:
            key = os.environ["GITGUARDIAN_API_KEY"]
            logger.debug("Using API key from $GITGUARDIAN_API_KEY")
        except KeyError:
            key = self.auth_config.get_instance_token(self.instance_name)
        return key

    def add_ignored_match(self, *args: Any, **kwargs: Any) -> None:
        return self.user_config.secret.add_ignored_match(*args, **kwargs)

    @property
    def saas_api_url(self) -> str:
        """
        The GIM SaaS instance (used to get JWT tokens).
        It is not configurable, but can be overridden with the
        GITGUARDIAN_SAAS_URL environment variable for tests.
        """
        if "api" in self.hmsl_url:  # case https://api.hasmysecretleaked.[...]
            default_value = self.hmsl_url.replace("hasmysecretleaked", "gitguardian")
        else:  # case https://hasmysecretleaked.[...]
            default_value = self.hmsl_url.replace("hasmysecretleaked", "api")
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
        logger.debug("Using API key for SaaS instancefrom config")
        dashboard_url = api_to_dashboard_url(self.saas_api_url)
        return self.auth_config.get_instance_token(dashboard_url)

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
