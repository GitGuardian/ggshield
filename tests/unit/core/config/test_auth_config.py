import os
import re
from copy import deepcopy
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from ggshield.core.config import Config
from ggshield.core.config.auth_config import (
    InstanceConfig,
    prepare_auth_config_dict_for_save,
)
from ggshield.core.config.token_store import (
    KEYRING_SENTINEL,
    KeyringTokenStore,
    reset_token_store,
)
from ggshield.core.config.utils import get_auth_config_filepath
from ggshield.core.errors import UnknownInstanceError
from tests.unit.conftest import write_text, write_yaml
from tests.unit.core.config.conftest import TEST_AUTH_CONFIG


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

        assert config.auth_config.instances[0].account.token_name == "my_token"
        assert config.auth_config.instances[0].default_token_lifetime == 1
        assert config.auth_config.default_token_lifetime == 2

        config_data = config.auth_config.to_dict()
        config_data = prepare_auth_config_dict_for_save(config_data)
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
            ValueError,
            match="Each GitGuardian instance should have exactly one account",
        ):
            Config()

    def test_invalid_format(self):
        """
        GIVEN an auth config file with invalid content
        WHEN loading AuthConfig
        THEN it raises
        """
        write_text(get_auth_config_filepath(), "Not a:\nyaml file.\n")
        expected_output = (
            f"{re.escape(str(get_auth_config_filepath()))} is not a valid YAML file:"
        )

        with pytest.raises(
            ValueError,
            match=expected_output,
        ):
            Config()

    def test_token_not_expiring(self):
        """
        GIVEN an auth config file with a token never expiring
        WHEN loading the AuthConfig
        THEN it works
        """
        raw_config = deepcopy(TEST_AUTH_CONFIG)
        raw_config["instances"][0]["accounts"][0]["expire_at"] = None
        write_yaml(get_auth_config_filepath(), raw_config)

        config = Config()

        assert config.auth_config.instances[0].account.expire_at is None

    def test_update(self):
        """
        GIVEN -
        WHEN modifying the default config
        THEN it's not persisted until .save() is called
        """
        config = Config()
        config.auth_config.get_or_create_instance("custom")

        with pytest.raises(UnknownInstanceError):
            Config().auth_config.get_instance("custom")

        config.save()

        instance = Config().auth_config.get_instance("custom")
        assert instance.url == "custom"

    def test_load_file_not_existing(self):
        """
        GIVEN the auth config file not existing
        WHEN loading the config
        THEN it works and has the default configuration
        """
        config = Config()

        assert config.instance_name == "https://dashboard.gitguardian.com"
        assert config.auth_config.instances == []

    def test_save_file_not_existing(self):
        """
        GIVEN a config object and the auth config file not existing
        WHEN saving the config
        THEN it works
        AND when loading the config again it has the correct values
        """
        config = Config()
        assert not os.path.exists(get_auth_config_filepath())

        config.auth_config.get_or_create_instance("custom")
        config.save()
        updated_config = Config()

        instance = updated_config.auth_config.get_instance("custom")
        assert instance.url == "custom"

    def test_timezone_aware_expired(self):
        """
        GIVEN a config with a configured instance
        WHEN loading the config
        THEN the instance expiration date is timezone aware
        """
        write_yaml(get_auth_config_filepath(), TEST_AUTH_CONFIG)
        config = Config()
        assert config.auth_config.instances[0].account.expire_at.tzinfo is not None

    def test_init_instance_config_with_expiration_date(self):
        token_data = {
            "type": "personal_access_token",
            "account_id": 8,
            "name": "ggshield token 2022-10-13",
            "scope": ["scan"],
            "expire_at": "2022-10-17T11:55:06Z",
        }
        instance = InstanceConfig(account=None, url="u")
        instance.init_account(token="tok", token_data=token_data)

        assert instance.account.expire_at == datetime(
            2022, 10, 17, 11, 55, 6, tzinfo=timezone.utc
        )


@pytest.fixture(autouse=False)
def _reset_token_store():
    reset_token_store()
    yield
    reset_token_store()


@pytest.mark.usefixtures("isolated_fs", "_reset_token_store")
class TestAuthConfigKeyring:
    """Tests for keyring integration in AuthConfig load/save."""

    @pytest.fixture(autouse=True)
    def _no_env_api_key(self, monkeypatch):
        """AuthConfig.load() skips keyring access when GITGUARDIAN_API_KEY is
        set in the environment. The session-wide test fixture sets a dummy
        value, so unset it here to exercise the keyring path."""
        monkeypatch.delenv("GITGUARDIAN_API_KEY", raising=False)

    def test_save_with_keyring(self, monkeypatch):
        """
        GIVEN a config with a cleartext token
        WHEN saving with keyring enabled
        THEN the token is stored in keyring and the YAML contains the sentinel
        """
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)

        write_yaml(get_auth_config_filepath(), TEST_AUTH_CONFIG)

        stored_tokens = {}
        mock_store = KeyringTokenStore()
        mock_store.store_token = MagicMock(
            side_effect=lambda url, token: stored_tokens.update({url: token})
        )
        mock_store.is_available = MagicMock(return_value=True)

        with patch(
            "ggshield.core.config.auth_config.get_token_store",
            return_value=mock_store,
        ):
            config = Config()
            original_token = config.auth_config.instances[0].account.token
            config.auth_config.save()

        # Verify token was sent to keyring
        assert "https://dashboard.gitguardian.com" in stored_tokens
        assert stored_tokens["https://dashboard.gitguardian.com"] == original_token

        # Verify YAML has sentinel, not cleartext
        import yaml

        with open(get_auth_config_filepath()) as f:
            saved_data = yaml.safe_load(f)

        for instance in saved_data["instances"]:
            for account in instance["accounts"]:
                assert account["token"] == KEYRING_SENTINEL

    def test_load_with_keyring(self, monkeypatch):
        """
        GIVEN a YAML config with keyring sentinel tokens
        WHEN loading with keyring enabled
        THEN tokens are hydrated from keyring
        """
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)

        # Write config with sentinel tokens
        sentinel_config = deepcopy(TEST_AUTH_CONFIG)
        for instance in sentinel_config["instances"]:
            for account in instance["accounts"]:
                account["token"] = KEYRING_SENTINEL
        write_yaml(get_auth_config_filepath(), sentinel_config)

        real_token = "real-token-from-keyring"
        mock_store = KeyringTokenStore()
        mock_store.get_token = MagicMock(return_value=real_token)
        mock_store.is_available = MagicMock(return_value=True)

        with patch(
            "ggshield.core.config.auth_config.get_token_store",
            return_value=mock_store,
        ):
            config = Config()

        assert config.auth_config.instances[0].account.token == real_token
        assert config.auth_config.instances[1].account.token == real_token

    def test_load_keyring_missing_token(self, monkeypatch):
        """
        GIVEN a YAML config with keyring sentinel
        WHEN the keyring returns None for a token
        THEN the account metadata is preserved but the token is cleared
        """
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)

        sentinel_config = deepcopy(TEST_AUTH_CONFIG)
        for instance in sentinel_config["instances"]:
            for account in instance["accounts"]:
                account["token"] = KEYRING_SENTINEL
        write_yaml(get_auth_config_filepath(), sentinel_config)

        mock_store = KeyringTokenStore()
        mock_store.get_token = MagicMock(return_value=None)
        mock_store.is_available = MagicMock(return_value=True)

        with patch(
            "ggshield.core.config.auth_config.get_token_store",
            return_value=mock_store,
        ):
            config = Config()

        # Account metadata is preserved, only the token is cleared
        assert config.auth_config.instances[0].account is not None
        assert config.auth_config.instances[0].account.token == ""
        assert config.auth_config.instances[0].account.token_name == "my_token"
        assert config.auth_config.instances[1].account is not None
        assert config.auth_config.instances[1].account.token == ""

    def test_migration_cleartext_to_keyring(self, monkeypatch):
        """
        GIVEN a legacy config with cleartext tokens
        WHEN loading and saving with keyring enabled
        THEN tokens are migrated to keyring and YAML gets sentinels
        """
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)

        write_yaml(get_auth_config_filepath(), TEST_AUTH_CONFIG)

        stored_tokens = {}
        mock_store = KeyringTokenStore()
        mock_store.store_token = MagicMock(
            side_effect=lambda url, token: stored_tokens.update({url: token})
        )
        mock_store.get_token = MagicMock(side_effect=lambda url: stored_tokens.get(url))
        mock_store.is_available = MagicMock(return_value=True)

        # Load with cleartext (no sentinel, so no keyring lookup)
        with patch(
            "ggshield.core.config.auth_config.get_token_store",
            return_value=mock_store,
        ):
            config = Config()

        # Tokens should be loaded from YAML (cleartext)
        original_token_0 = TEST_AUTH_CONFIG["instances"][0]["accounts"][0]["token"]
        original_token_1 = TEST_AUTH_CONFIG["instances"][1]["accounts"][0]["token"]
        assert config.auth_config.instances[0].account.token == original_token_0
        assert config.auth_config.instances[1].account.token == original_token_1

        # Save triggers migration
        with patch(
            "ggshield.core.config.auth_config.get_token_store",
            return_value=mock_store,
        ):
            config.auth_config.save()

        # Verify tokens were stored in keyring
        assert len(stored_tokens) == 2
        assert stored_tokens["https://dashboard.gitguardian.com"] == original_token_0

        # Verify YAML now has sentinels
        import yaml

        with open(get_auth_config_filepath()) as f:
            saved_data = yaml.safe_load(f)
        for instance in saved_data["instances"]:
            for account in instance["accounts"]:
                assert account["token"] == KEYRING_SENTINEL

    def test_save_fallback_on_keyring_error(self, monkeypatch, capsys):
        """
        GIVEN a config with tokens
        WHEN keyring raises an error during save
        THEN cleartext tokens are preserved in YAML and the user is warned with
             an actionable fix command (rather than failing silently)
        """
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)

        write_yaml(get_auth_config_filepath(), TEST_AUTH_CONFIG)

        mock_store = KeyringTokenStore()
        mock_store.store_token = MagicMock(side_effect=RuntimeError("keyring broken"))
        mock_store.is_available = MagicMock(return_value=True)

        with patch(
            "ggshield.core.config.auth_config.get_token_store",
            return_value=mock_store,
        ):
            config = Config()
            config.auth_config.save()

        # Verify YAML still has cleartext tokens (not sentinels)
        import yaml

        with open(get_auth_config_filepath()) as f:
            saved_data = yaml.safe_load(f)

        original_token_0 = TEST_AUTH_CONFIG["instances"][0]["accounts"][0]["token"]
        assert saved_data["instances"][0]["accounts"][0]["token"] == original_token_0

        # The failure is surfaced to the user, not just logged
        err = capsys.readouterr().err
        assert "Could not store the token" in err
        assert "cleartext" in err
        assert "ggshield auth status" in err
        assert "ggshield auth login" in err

    def test_save_announces_cleartext_migration(self, monkeypatch, capsys):
        """
        GIVEN a config whose tokens are cleartext on disk
        WHEN saving with a working keyring
        THEN the user is told the tokens were migrated to the credential store
        """
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)

        write_yaml(get_auth_config_filepath(), TEST_AUTH_CONFIG)

        mock_store = KeyringTokenStore()
        mock_store.store_token = MagicMock()
        mock_store.is_available = MagicMock(return_value=True)

        with patch(
            "ggshield.core.config.auth_config.get_token_store",
            return_value=mock_store,
        ):
            config = Config()
            config.auth_config.save()

        out = capsys.readouterr().err
        assert "migrated" in out
        assert "https://dashboard.gitguardian.com" in out

    def test_save_silent_when_already_in_keyring(self, monkeypatch, capsys):
        """
        GIVEN a config already migrated (sentinel on disk, token from keyring)
        WHEN saving again
        THEN no migration message is shown (avoid noise on routine re-saves)
        """
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)

        sentinel_config = deepcopy(TEST_AUTH_CONFIG)
        for instance in sentinel_config["instances"]:
            for account in instance["accounts"]:
                account["token"] = KEYRING_SENTINEL
        write_yaml(get_auth_config_filepath(), sentinel_config)

        mock_store = KeyringTokenStore()
        mock_store.store_token = MagicMock()
        mock_store.get_token = MagicMock(return_value="real-token-from-keyring")
        mock_store.is_available = MagicMock(return_value=True)

        with patch(
            "ggshield.core.config.auth_config.get_token_store",
            return_value=mock_store,
        ):
            config = Config()
            config.auth_config.save()

        out = capsys.readouterr().err
        assert "migrated" not in out

    def test_load_keyring_get_token_exception(self, monkeypatch):
        """
        GIVEN a YAML config with keyring sentinel
        WHEN get_token raises an exception
        THEN the account metadata is preserved and the token is cleared
        """
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)

        sentinel_config = deepcopy(TEST_AUTH_CONFIG)
        for instance in sentinel_config["instances"]:
            for account in instance["accounts"]:
                account["token"] = KEYRING_SENTINEL
        write_yaml(get_auth_config_filepath(), sentinel_config)

        mock_store = KeyringTokenStore()
        mock_store.get_token = MagicMock(side_effect=RuntimeError("keyring locked"))
        mock_store.is_available = MagicMock(return_value=True)

        with patch(
            "ggshield.core.config.auth_config.get_token_store",
            return_value=mock_store,
        ):
            config = Config()

        assert config.auth_config.instances[0].account is not None
        assert config.auth_config.instances[0].account.token == ""
        assert config.auth_config.instances[0].account.token_name == "my_token"

    def test_load_sentinel_without_keyring(self, monkeypatch):
        """
        GIVEN a YAML config with keyring sentinel tokens
        WHEN loading with GGSHIELD_NO_KEYRING=1 (keyring disabled)
        THEN the token is cleared and a warning is logged
        """
        monkeypatch.setenv("GGSHIELD_NO_KEYRING", "1")

        sentinel_config = deepcopy(TEST_AUTH_CONFIG)
        for instance in sentinel_config["instances"]:
            for account in instance["accounts"]:
                account["token"] = KEYRING_SENTINEL
        write_yaml(get_auth_config_filepath(), sentinel_config)

        config = Config()

        # Sentinel is detected and cleared rather than sent as an API token
        assert config.auth_config.instances[0].account is not None
        assert config.auth_config.instances[0].account.token == ""
        assert config.auth_config.instances[1].account is not None
        assert config.auth_config.instances[1].account.token == ""

    def test_load_skips_keyring_when_env_api_key_set(self, monkeypatch):
        """
        GIVEN a YAML config with keyring sentinel tokens AND GITGUARDIAN_API_KEY set
        WHEN loading
        THEN the keyring is not accessed (no prompt to the user) since the
             env-provided key would override stored tokens anyway
        """
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)
        monkeypatch.setenv("GITGUARDIAN_API_KEY", "env-token")

        sentinel_config = deepcopy(TEST_AUTH_CONFIG)
        for instance in sentinel_config["instances"]:
            for account in instance["accounts"]:
                account["token"] = KEYRING_SENTINEL
        write_yaml(get_auth_config_filepath(), sentinel_config)

        mock_store = KeyringTokenStore()
        mock_store.get_token = MagicMock()
        mock_store.is_available = MagicMock()

        with patch(
            "ggshield.core.config.auth_config.get_token_store",
            return_value=mock_store,
        ) as mock_get_store:
            Config()

        mock_get_store.assert_not_called()
        mock_store.is_available.assert_not_called()
        mock_store.get_token.assert_not_called()

    def test_file_store_preserves_cleartext(self, monkeypatch):
        """
        GIVEN GGSHIELD_NO_KEYRING=1
        WHEN saving config
        THEN tokens remain in cleartext in YAML
        """
        monkeypatch.setenv("GGSHIELD_NO_KEYRING", "1")

        write_yaml(get_auth_config_filepath(), TEST_AUTH_CONFIG)
        config = Config()
        config.auth_config.save()

        import yaml

        with open(get_auth_config_filepath()) as f:
            saved_data = yaml.safe_load(f)

        original_token = TEST_AUTH_CONFIG["instances"][0]["accounts"][0]["token"]
        assert saved_data["instances"][0]["accounts"][0]["token"] == original_token
