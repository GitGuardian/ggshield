import os
import sys
from copy import deepcopy
from enum import IntEnum
from pathlib import Path
from typing import Optional

import pytest

from ggshield.core.config import AccountConfig, Config, InstanceConfig
from ggshield.core.config.errors import UnknownInstanceError
from ggshield.core.config.utils import get_auth_config_filepath, load_yaml
from ggshield.core.constants import DEFAULT_LOCAL_CONFIG_PATH
from ggshield.core.utils import dashboard_to_api_url
from tests.conftest import write_yaml
from tests.core.config.conftest import TEST_AUTH_CONFIG


class InstanceNamePriority(IntEnum):
    GLOBAL = 0
    LOCAL = 1
    ENV = 2
    CMDLINE = 3


INSTANCES = [f"https://{x.lower()}.com" for x in InstanceNamePriority.__members__]


@pytest.fixture(autouse=True)
def env_vars(monkeypatch):
    monkeypatch.delenv("GITGUARDIAN_INSTANCE", raising=False)
    monkeypatch.delenv("GITGUARDIAN_API_URL", raising=False)
    monkeypatch.delenv("GITGUARDIAN_API_KEY", raising=False)


@pytest.mark.usefixtures("isolated_fs")
class TestConfig:
    def set_instances(
        self, local_filepath: str, global_filepath: str, priority: InstanceNamePriority
    ):
        auth_config_data = deepcopy(TEST_AUTH_CONFIG)
        for url in INSTANCES:
            config_dict = deepcopy(auth_config_data["instances"][0])
            config_dict["url"] = url
            auth_config_data["instances"].append(config_dict)
        if priority >= InstanceNamePriority.LOCAL:
            write_yaml(
                local_filepath, {"instance": INSTANCES[InstanceNamePriority.LOCAL]}
            )
        else:
            if os.path.isfile(local_filepath):
                os.remove(local_filepath)
        if priority >= InstanceNamePriority.GLOBAL:
            write_yaml(
                global_filepath, {"instance": INSTANCES[InstanceNamePriority.GLOBAL]}
            )
        else:
            if os.path.isfile(global_filepath):
                os.remove(global_filepath)
        write_yaml(get_auth_config_filepath(), auth_config_data)

    @pytest.mark.parametrize(
        "priority",
        (
            InstanceNamePriority.GLOBAL,
            InstanceNamePriority.LOCAL,
            InstanceNamePriority.ENV,
            InstanceNamePriority.CMDLINE,
        ),
    )
    def test_instance_name_priority(
        self,
        local_config_path,
        global_config_path,
        priority: InstanceNamePriority,
        monkeypatch,
    ):
        """
        GIVEN different instances defined in the different possible sources:
          - manually set on the command-line
          - env variable
          - local user config
          - global user config
        WHEN reading the config instance
        THEN it respects the expected priority
        """
        if priority >= InstanceNamePriority.ENV:
            monkeypatch.setenv(
                "GITGUARDIAN_INSTANCE", INSTANCES[InstanceNamePriority.ENV]
            )

        self.set_instances(
            local_filepath=local_config_path,
            global_filepath=global_config_path,
            priority=priority,
        )
        config = Config()
        if priority >= InstanceNamePriority.CMDLINE:
            config.set_cmdline_instance_name(INSTANCES[InstanceNamePriority.CMDLINE])

        expected_instance = INSTANCES[priority]
        assert config.instance_name == expected_instance
        assert config.dashboard_url == expected_instance
        assert config.api_url == dashboard_to_api_url(expected_instance)

    def test_instance_not_in_auth_config(self):
        """
        GIVEN a config with a current instance not being a valid configured instance
        WHEN reading config.api_key
        THEN it raises
        """
        config = Config()
        config.instance = "toto"

        with pytest.raises(UnknownInstanceError, match="Unknown instance: 'toto'"):
            config.api_key

    @pytest.mark.parametrize(
        [
            "env_var_key",
            "cmdline_instance",
            "env_var_instance",
            "user_config_instance",
            "expected_api_key",
        ],
        [
            [
                "api_key_env",
                "https://instance1.com",
                "https://instance2.com",
                "https://instance3.com",
                "api_key_env",
            ],
            [
                None,
                "https://instance1.com",
                "https://instance2.com",
                "https://instance3.com",
                "api_key_instance1.com",
            ],
            [
                None,
                None,
                "https://instance2.com",
                "https://instance3.com",
                "api_key_instance2.com",
            ],
            [
                None,
                None,
                None,
                "https://instance3.com",
                "api_key_instance3.com",
            ],
        ],
    )
    def test_api_key_priority(
        self,
        env_var_key: Optional[str],
        cmdline_instance: Optional[str],
        env_var_instance: Optional[str],
        user_config_instance: Optional[str],
        expected_api_key: str,
        monkeypatch,
    ):
        """
        GIVEN different instances defined, and a gitguardian api key being manually passed
        or not to the config, and the env var being manually set or not
        WHEN reading the API key to use
        THEN it respects the priority:
        - env var API key
        - from cmdline instance
        - from env var instance
        - from user config instance (local then global)
        """
        if env_var_key:
            monkeypatch.setenv("GITGUARDIAN_API_KEY", env_var_key)

        if env_var_instance:
            monkeypatch.setenv("GITGUARDIAN_INSTANCE", env_var_instance)

        config = Config()
        if cmdline_instance:
            config.set_cmdline_instance_name(cmdline_instance)
        if not env_var_instance:
            config.user_config.instance = user_config_instance

        def set_instance(url):
            if url is None:
                return
            api_key = url.replace("https://", "api_key_")
            config.auth_config.instances.append(
                InstanceConfig(
                    url=url,
                    account=AccountConfig(
                        workspace_id=1,
                        token=api_key,
                        type="PAT",
                        token_name="name",
                        expire_at=None,
                    ),
                )
            )

        set_instance(cmdline_instance)
        set_instance(env_var_instance)
        set_instance(user_config_instance)

        assert config.api_key == expected_api_key

    def test_user_config_url_no_configured_instance(self):
        """
        GIVEN a bare auth config, but urls configured in the user config
        WHEN reading api_url/dashboard_url
        THEN it works
        """

        config = Config()

        assert config.auth_config.instances == []

        # from the default test env vars:
        assert config.api_url == "https://api.gitguardian.com"
        assert config.dashboard_url == "https://dashboard.gitguardian.com"

    def test_v1_in_api_url_env(self, capsys, monkeypatch):
        """
        GIVEN an API URL ending with /v1 configured via env var
        WHEN loading the config
        THEN writes a warning to stderr
        """
        monkeypatch.setitem(
            os.environ, "GITGUARDIAN_API_URL", "https://api.gitguardian.com/v1"
        )
        config = Config()
        api_url = config.api_url
        out, err = capsys.readouterr()
        sys.stdout.write(out)
        sys.stderr.write(err)

        assert api_url == "https://api.gitguardian.com"
        assert "Unexpected /v1 path in your URL configuration" in err

    def test_v1_in_api_url_local_config(self, capsys, local_config_path):
        """
        GIVEN an API URL ending with /v1 configured via in the local config file
        WHEN loading the config
        THEN writes a warning to stderr
        """
        write_yaml(
            local_config_path,
            {
                "verbose": False,
                "show_secrets": True,
                "api_url": "https://api.gitguardian.com/v1",
            },
        )

        config = Config()
        api_url = config.api_url
        out, err = capsys.readouterr()
        sys.stdout.write(out)
        sys.stderr.write(err)

        assert api_url == "https://api.gitguardian.com"
        assert "Unexpected /v1 path in your URL configuration" in err

    def test_v1_in_api_url_global_config(self, capsys, global_config_path):
        """
        GIVEN an API URL ending with /v1 configured in the global config file
        WHEN loading the config
        THEN writes a warning to stderr
        """
        write_yaml(
            global_config_path,
            {
                "verbose": False,
                "show_secrets": True,
                "api_url": "https://api.gitguardian.com/v1",
            },
        )

        Config()
        out, err = capsys.readouterr()
        sys.stdout.write(out)
        sys.stderr.write(err)

        assert "Unexpected /v1 path in your URL configuration" in err

    def test_updating_config_not_from_default_local_config_path(
        self, local_config_path
    ):
        """
        GIVEN a ggshield config stored in .gitguardian (not .gitguardian.yaml, the
        default filename)
        WHEN saving the config
        THEN .gitguardian is updated
        AND .gitguardian.yaml is not created
        """
        write_yaml(
            local_config_path,
            {
                "instance": "https://before.com",
            },
        )

        config = Config()
        config.user_config.instance = "https://after.com"
        config.save()

        assert not Path(DEFAULT_LOCAL_CONFIG_PATH).exists()

        dct = load_yaml(local_config_path)
        assert dct["instance"] == "https://after.com"
