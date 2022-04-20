import os
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from ggshield.config import (
    AccountConfig,
    Config,
    InstanceConfig,
    UnknownInstanceError,
    get_auth_config_filepath,
    replace_in_keys,
)
from ggshield.utils import dashboard_to_api_url


@pytest.fixture
def local_config_path(tmp_path):
    dirpath = os.path.join(tmp_path, "ggshield", "local")
    filepath = os.path.join(
        tmp_path, "ggshield", "local", "test_local_gitguardian.yaml"
    )
    Path(dirpath).mkdir(parents=True, exist_ok=True)
    if os.path.isfile(filepath):
        os.remove(filepath)
    yield filepath


@pytest.fixture()
def global_config_path(tmp_path):
    dirpath = os.path.join(tmp_path, "ggshield", "global")
    filepath = os.path.join(
        tmp_path, "ggshield", "global", "test_global_gitguardian.yaml"
    )
    Path(dirpath).mkdir(parents=True, exist_ok=True)
    if os.path.isfile(filepath):
        os.remove(filepath)
    yield filepath


@pytest.fixture(autouse=True)
def configure_test_constants(local_config_path, global_config_path, tmp_path):
    with patch("ggshield.config.DEFAULT_LOCAL_CONFIG_PATH", local_config_path,), patch(
        "ggshield.config.LOCAL_CONFIG_PATHS", [local_config_path]
    ), patch(
        "ggshield.config.GLOBAL_CONFIG_FILENAMES",
        [os.path.split(global_config_path)[-1]],
    ), patch(
        "ggshield.cache.CACHE_FILENAME", "test_cache_ggshield"
    ), patch(
        "ggshield.config.get_global_path",
        lambda filename: os.path.join(tmp_path, "ggshield", "global", filename),
    ):
        yield


@pytest.fixture(autouse=True)
def env_vars(monkeypatch):
    api_key = os.getenv("TEST_GITGUARDIAN_API_KEY", "1234567890")
    monkeypatch.setenv("GITGUARDIAN_API_URL", "https://api.gitguardian.com")
    monkeypatch.setenv("GITGUARDIAN_API_KEY", api_key)


def write_text(filename: str, text: str):
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def write_yaml(filename: str, data: Any):
    path = Path(filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as file:
        file.write(yaml.dump(data))


class TestUtils:
    def test_replace_in_keys(self):
        data = {"last-found-secrets": {"XXX"}}
        replace_in_keys(data, "-", "_")
        assert data == {"last_found_secrets": {"XXX"}}
        replace_in_keys(data, "_", "-")
        assert data == {"last-found-secrets": {"XXX"}}


@pytest.mark.usefixtures("isolated_fs")
class TestUserConfig:
    def test_parsing_error(cli_fs_runner, capsys, monkeypatch, tmp_path):
        filepath = os.path.join(tmp_path, "test_local_gitguardian.yml")
        monkeypatch.setattr("ggshield.config.LOCAL_CONFIG_PATHS", [filepath])
        monkeypatch.setattr("ggshield.config.GLOBAL_CONFIG_FILENAMES", [])
        write_text(filepath, "Not a:\nyaml file.\n")

        Config()
        out, err = capsys.readouterr()
        sys.stdout.write(out)
        sys.stderr.write(err)

        assert f"Parsing error while reading {filepath}:" in out

    def test_display_options(self, cli_fs_runner, local_config_path, monkeypatch):
        write_yaml(local_config_path, {"verbose": True, "show_secrets": True})
        monkeypatch.setattr("ggshield.config.GLOBAL_CONFIG_FILENAMES", [])

        config = Config()
        assert config.verbose is True
        assert config.show_secrets is True

    def test_unknown_option(
        self, cli_fs_runner, capsys, local_config_path, monkeypatch
    ):
        write_yaml(local_config_path, {"verbosity": True})
        monkeypatch.setattr("ggshield.config.GLOBAL_CONFIG_FILENAMES", [])

        Config()
        captured = capsys.readouterr()
        assert "Unrecognized key in config" in captured.out

    def test_display_options_inheritance(
        self, cli_fs_runner, local_config_path, global_config_path
    ):
        write_yaml(
            local_config_path,
            {
                "verbose": True,
                "show_secrets": False,
                "api_url": "https://api.gitguardian.com",
            },
        )
        write_yaml(
            global_config_path,
            {
                "verbose": False,
                "show_secrets": True,
                "api_url": "https://api.gitguardian.com2",
            },
        )

        config = Config()
        assert config.verbose is True
        assert config.show_secrets is False
        assert config.user_config.api_url == "https://api.gitguardian.com"

    def test_exclude_regex(self, cli_fs_runner, local_config_path, monkeypatch):
        write_yaml(local_config_path, {"paths-ignore": ["/tests/"]})
        monkeypatch.setattr("ggshield.config.GLOBAL_CONFIG_FILENAMES", [])

        config = Config()
        assert r"/tests/" in config.paths_ignore

    def test_accumulation_matches(
        self, cli_fs_runner, local_config_path, global_config_path
    ):
        write_yaml(
            local_config_path,
            {
                "matches_ignore": [
                    {"name": "", "match": "one"},
                    {"name": "", "match": "two"},
                ]
            },
        )
        write_yaml(
            global_config_path,
            {"matches_ignore": [{"name": "", "match": "three"}]},
        )
        config = Config()
        assert config.matches_ignore == [
            {"match": "three", "name": ""},
            {"match": "one", "name": ""},
            {"match": "two", "name": ""},
        ]


@pytest.mark.usefixtures("isolated_fs")
class TestAuthConfig:
    default_config = {
        "default-instance": "default",
        "default-token-lifetime": 7,  # days
        "instances": {
            "default": {
                "name": "default",
                "url": "https://dashboard.gitguardian.com",
                "default-token-lifetime": 1,
                "accounts": [
                    {
                        "account-id": 23,
                        "token": "62890f237c703c92fbda8236ec2a055ac21332a46115005c976d68b900535fb5",
                        "type": "pat",
                        "token-name": "my_token",
                        "expire-at": "2022-02-23T12:34:56+00:00",
                    }
                ],
            },
            "dashboard.onprem.example.com": {
                "name": None,
                "url": "https://dashboard.onprem.example.com",
                "default-token-lifetime": 0,  # no expiry
                "accounts": [
                    {
                        "account-id": 1,
                        "token": "8ecffbaeedcd2f090546efeed3bc48a5f4a04a1196637aef6b3f6bbcfd58a96b",
                        "type": "sat",
                        "token-name": "my_other_token",
                        "expire-at": "2022-02-24T12:34:56+00:00",
                    }
                ],
            },
        },
    }

    def test_load(self):
        """
        GIVEN a default auth config
        WHEN loading the config
        THEN when serializing it again, it matches the data.
        """
        write_yaml(get_auth_config_filepath(), self.default_config)

        config = Config()

        assert config.instances["default"].account.token_name == "my_token"

        config_data = config.auth_config.to_dict()
        replace_in_keys(config_data, old_char="_", new_char="-")
        assert config_data == self.default_config

    @pytest.mark.parametrize("n", [0, 2])
    def test_no_account(self, n):
        """
        GIVEN an auth config with a instance with 0 or more than 1 accounts
        WHEN loading the AuthConfig
        THEN it raises
        """
        raw_config = deepcopy(self.default_config)
        raw_config["instances"]["default"]["accounts"] = (
            raw_config["instances"]["default"]["accounts"] * n
        )
        write_yaml(get_auth_config_filepath(), raw_config)

        with pytest.raises(
            AssertionError,
            match="Each GitGuardian instance should have exactly one account",
        ):
            Config()

    def test_invalid_format(self, capsys):
        """
        GIVEN an auth config file with invalid content
        WHEN loading AuthConfig
        THEN it raises
        """
        write_text(get_auth_config_filepath(), "Not a:\nyaml file.\n")

        Config()
        out, err = capsys.readouterr()
        sys.stdout.write(out)
        sys.stderr.write(err)

        assert f"Parsing error while reading {get_auth_config_filepath()}:" in out

    def test_token_not_expiring(self):
        """
        GIVEN an auth config file with a token never expiring
        WHEN loading the AuthConfig
        THEN it works
        """
        raw_config = deepcopy(self.default_config)
        raw_config["instances"]["default"]["accounts"][0]["expire-at"] = None
        write_yaml(get_auth_config_filepath(), raw_config)

        config = Config()

        assert config.instances["default"].account.expire_at is None

    def test_update(self):
        """
        GIVEN -
        WHEN modifiying the default config
        THEN it's not persisted until .save() is called
        """
        config = Config()
        config.default_instance = "custom"

        assert Config().default_instance != "custom"

        config.save()

        assert Config().default_instance == "custom"

    def test_load_file_not_existing(self):
        """
        GIVEN the auth config file not existing
        WHEN loading the config
        THEN it works and has the default configuration
        """
        config = Config()

        assert config.default_instance == "https://dashboard.gitguardian.com"
        assert config.default_token_lifetime is None
        assert config.instances == {}

    def test_save_file_not_existing(self):
        """
        GIVEN a config object and the auth config file not existing
        WHEN saving the config
        THEN it works and when loading the config again it has the correct values
        """
        config = Config()
        try:
            os.remove(get_auth_config_filepath())
        except FileNotFoundError:
            pass

        config.default_instance = "custom"
        config.save()
        updated_config = Config()

        assert updated_config.default_instance == "custom"

    def test_timezone_aware_expired(self):
        """
        GIVEN a config with a configured instance
        WHEN loading the config
        THEN the instance expiration date is timezone aware
        """
        write_yaml(get_auth_config_filepath(), self.default_config)
        config = Config()
        assert config.instances["default"].account.expire_at.tzinfo is not None


@pytest.mark.usefixtures("isolated_fs")
class TestConfig:
    def set_instances(
        self,
        local_filepath,
        global_filepath,
        local_instance=None,
        global_instance=None,
        default_instance=None,
    ):
        auth_config_data = deepcopy(TestAuthConfig.default_config)
        for i in range(1, 6):
            url = f"https://instance{i}.com"
            auth_config_data["instances"][url] = deepcopy(
                auth_config_data["instances"]["default"]
            )
            auth_config_data["instances"][url]["url"] = url
        if local_instance:
            write_yaml(local_filepath, {"dashboard-url": local_instance})
        else:
            if os.path.isfile(local_filepath):
                os.remove(local_filepath)
        if global_instance:
            write_yaml(global_filepath, {"dashboard-url": global_instance})
        else:
            if os.path.isfile(global_filepath):
                os.remove(global_filepath)
        if default_instance:
            auth_config_data["default-instance"] = default_instance
        write_yaml(get_auth_config_filepath(), auth_config_data)

    @pytest.mark.parametrize(
        [
            "current_instance",
            "env_instance",
            "local_instance",
            "global_instance",
            "default_instance",
            "expected_instance",
        ],
        [
            pytest.param(
                "https://instance1.com",
                "https://instance2.com",
                "https://instance3.com",
                "https://instance4.com",
                "https://instance5.com",
                "https://instance1.com",
                id="current_instance",
            ),
            pytest.param(
                None,
                "https://instance2.com",
                "https://instance3.com",
                "https://instance4.com",
                "https://instance5.com",
                "https://instance2.com",
                id="env_instance",
            ),
            pytest.param(
                None,
                None,
                "https://instance3.com",
                "https://instance4.com",
                "https://instance5.com",
                "https://instance3.com",
                id="local_instance",
            ),
            pytest.param(
                None,
                None,
                None,
                "https://instance4.com",
                "https://instance5.com",
                "https://instance4.com",
                id="global_instance",
            ),
            pytest.param(
                None,
                None,
                None,
                None,
                "https://instance5.com",
                "https://instance5.com",
                id="default_instance",
            ),
        ],
    )
    def test_instance_name_priority(
        self,
        current_instance,
        env_instance,
        local_instance,
        global_instance,
        default_instance,
        expected_instance,
        local_config_path,
        global_config_path,
    ):
        """
        GIVEN different instances defined in the different possible sources:
          - manually set on the config
          - env variable
          - local user config
          - global user config
          - default instance in the auth config
        WHEN reading the config instance
        THEN it respects the expected priority
        """
        if env_instance:
            os.environ["GITGUARDIAN_URL"] = env_instance
        elif "GITGUARDIAN_URL" in os.environ:
            del os.environ["GITGUARDIAN_URL"]
        if "GITGUARDIAN_API_URL" in os.environ:
            del os.environ["GITGUARDIAN_API_URL"]

        self.set_instances(
            local_instance=local_instance,
            global_instance=global_instance,
            default_instance=default_instance,
            local_filepath=local_config_path,
            global_filepath=global_config_path,
        )
        config = Config()
        config.current_instance = current_instance

        assert config.instance_name == expected_instance
        assert config.dashboard_url == expected_instance
        assert config.api_url == dashboard_to_api_url(expected_instance)

    def test_instance_not_in_auth_config(self):
        """
        GIVEN a config with a current instance not being a valid configured instance
        WHEN reading config.api_key
        THEN it raises
        """
        if "GITGUARDIAN_API_KEY" in os.environ:
            del os.environ["GITGUARDIAN_API_KEY"]
        config = Config()
        config.current_instance = "toto"

        with pytest.raises(UnknownInstanceError, match="Unknown instance: 'toto'"):
            config.api_key

    @pytest.mark.parametrize(
        [
            "manual_key",
            "env_var_key",
            "manual_instance",
            "env_var_instance",
            "user_config_instance",
            "default_instance",
            "expected_api_key",
        ],
        [
            [
                "api_key_manual",
                "api_key_env",
                "https://instance1.com",
                "https://instance2.com",
                "https://instance3.com",
                "https://instance4.com",
                "api_key_manual",
            ],
            [
                None,
                "api_key_env",
                "https://instance1.com",
                "https://instance2.com",
                "https://instance3.com",
                "https://instance4.com",
                "api_key_env",
            ],
            [
                None,
                None,
                "https://instance1.com",
                "https://instance2.com",
                "https://instance3.com",
                "https://instance4.com",
                "api_key_instance1.com",
            ],
            [
                None,
                None,
                None,
                "https://instance2.com",
                "https://instance3.com",
                "https://instance4.com",
                "api_key_instance2.com",
            ],
            [
                None,
                None,
                None,
                None,
                "https://instance3.com",
                "https://instance4.com",
                "api_key_instance3.com",
            ],
            [
                None,
                None,
                None,
                None,
                None,
                "https://instance4.com",
                "api_key_instance4.com",
            ],
        ],
    )
    def test_api_key_priority(
        self,
        manual_key,
        env_var_key,
        manual_instance,
        env_var_instance,
        user_config_instance,
        default_instance,
        expected_api_key,
    ):
        """
        GIVEN different instances defined, and a gitguardian api key being manually passed
        or not to the config, and the env var being manually set or not
        WHEN reading the API key to use
        THEN it respects the priority:
        - manual API key
        - env var API key
        - from manual instance
        - from env var instance
        - from user config instance (local then global)
        - from default instance
        """
        if env_var_key:
            os.environ["GITGUARDIAN_API_KEY"] = env_var_key
        elif "GITGUARDIAN_API_KEY" in os.environ:
            del os.environ["GITGUARDIAN_API_KEY"]
        if env_var_instance:
            os.environ["GITGUARDIAN_URL"] = env_var_instance
        elif "GITGUARDIAN_URL" in os.environ:
            del os.environ["GITGUARDIAN_URL"]
        if "GITGUARDIAN_API_URL" in os.environ:
            del os.environ["GITGUARDIAN_API_URL"]

        config = Config()
        if manual_key:
            config.current_token = manual_key
        if manual_instance:
            config.current_instance = manual_instance
        if not env_var_instance:
            config.user_config.dashboard_url = user_config_instance
        config.auth_config.default_instance = default_instance

        def set_instance(url):
            if url is None:
                return
            api_key = url.replace("https://", "api_key_")
            config.auth_config.instances[url] = InstanceConfig(
                url=url,
                account=AccountConfig(
                    account_id=1,
                    token=api_key,
                    type="PAT",
                    token_name="name",
                    expire_at=None,
                ),
            )

        set_instance(manual_instance)
        set_instance(env_var_instance)
        set_instance(user_config_instance)
        set_instance(default_instance)

        assert config.api_key == expected_api_key

    def test_user_confi_url_no_configured_instance(self):
        """
        GIVEN a bare auth config, but urls configured in the user config
        WHEN reading api_url/dashboard_url
        THEN it works
        """

        config = Config()

        assert config.auth_config.instances == {}

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
        Config()
        out, err = capsys.readouterr()
        sys.stdout.write(out)
        sys.stderr.write(err)

        assert "[Warning] unexpected /v1 path in your URL configuration" in err

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

        Config()
        out, err = capsys.readouterr()
        sys.stdout.write(out)
        sys.stderr.write(err)

        assert "[Warning] unexpected /v1 path in your URL configuration" in err

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

        assert "[Warning] unexpected /v1 path in your URL configuration" in err
