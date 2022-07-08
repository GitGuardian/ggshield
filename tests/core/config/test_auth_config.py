import os
import sys
from copy import deepcopy

import pytest

from ggshield.core.config import Config
from ggshield.core.config.auth_config import (
    AuthConfigSchema,
    prepare_auth_config_dict_for_save,
)
from ggshield.core.config.utils import get_auth_config_filepath, replace_in_keys
from tests.conftest import write_text, write_yaml
from tests.core.config.conftest import TEST_AUTH_CONFIG


@pytest.fixture(autouse=True)
def env_vars(monkeypatch):
    monkeypatch.setenv("GITGUARDIAN_API_URL", "https://api.gitguardian.com")


@pytest.mark.usefixtures("isolated_fs")
class TestAuthConfig:
    def test_load(self):
        """
        GIVEN a default auth config
        WHEN loading the config
        THEN when serializing it again, it matches the data.
        """
        write_yaml(get_auth_config_filepath(), TEST_AUTH_CONFIG)

        config = Config()

        assert config.instances[0].account.token_name == "my_token"
        assert config.instances[0].default_token_lifetime == 1
        assert config.auth_config.default_token_lifetime == 2

        config_data = AuthConfigSchema().dump(config.auth_config)
        config_data = prepare_auth_config_dict_for_save(config_data)
        replace_in_keys(config_data, old_char="_", new_char="-")
        assert config_data == TEST_AUTH_CONFIG

    @pytest.mark.parametrize("n", [0, 2])
    def test_no_account(self, n):
        """
        GIVEN an auth config with a instance with 0 or more than 1 accounts
        WHEN loading the AuthConfig
        THEN it raises
        """
        raw_config = deepcopy(TEST_AUTH_CONFIG)
        raw_config["instances"][0]["accounts"] = (
            raw_config["instances"][0]["accounts"] * n
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

        assert f"Parsing error while reading {get_auth_config_filepath()}:" in err

    def test_token_not_expiring(self):
        """
        GIVEN an auth config file with a token never expiring
        WHEN loading the AuthConfig
        THEN it works
        """
        raw_config = deepcopy(TEST_AUTH_CONFIG)
        raw_config["instances"][0]["accounts"][0]["expire-at"] = None
        write_yaml(get_auth_config_filepath(), raw_config)

        config = Config()

        assert config.instances[0].account.expire_at is None

    def test_update(self):
        """
        GIVEN -
        WHEN modifying the default config
        THEN it's not persisted until .save() is called
        """
        config = Config()
        config.instance = "custom"

        assert Config().instance != "custom"

        config.save()

        assert Config().instance == "custom"

    def test_load_file_not_existing(self):
        """
        GIVEN the auth config file not existing
        WHEN loading the config
        THEN it works and has the default configuration
        """
        config = Config()

        assert config.instance_name == "https://dashboard.gitguardian.com"
        assert config.instances == []

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

        config.instance = "custom"
        config.save()
        updated_config = Config()

        assert updated_config.instance == "custom"

    def test_timezone_aware_expired(self):
        """
        GIVEN a config with a configured instance
        WHEN loading the config
        THEN the instance expiration date is timezone aware
        """
        write_yaml(get_auth_config_filepath(), TEST_AUTH_CONFIG)
        config = Config()
        assert config.instances[0].account.expire_at.tzinfo is not None
