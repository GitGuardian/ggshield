import os
from typing import Any, Mapping, Optional

import click

from ggshield.core.config.auth_config import AuthConfig
from ggshield.core.config.user_config import UserConfig
from ggshield.core.config.utils import get_attr_mapping
from ggshield.core.constants import DEFAULT_DASHBOARD_URL
from ggshield.core.utils import api_to_dashboard_url, clean_url, dashboard_to_api_url


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
            return os.environ["GITGUARDIAN_INSTANCE"]
        except KeyError:
            pass

        try:
            name = os.environ["GITGUARDIAN_API_URL"]
        except KeyError:
            pass
        else:
            return api_to_dashboard_url(name, warn=True)

        if self.user_config.instance:
            return self.user_config.instance

        return DEFAULT_DASHBOARD_URL

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
        The dashboard URL to use to use the dashboard
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
            return os.environ["GITGUARDIAN_API_KEY"]
        except KeyError:
            return self.auth_config.get_instance_token(self.instance_name)

    def add_ignored_match(self, *args: Any, **kwargs: Any) -> None:
        return self.user_config.secret.add_ignored_match(*args, **kwargs)
