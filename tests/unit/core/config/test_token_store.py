from unittest.mock import MagicMock, patch

import pytest

from ggshield.core.config.token_store import (
    KEYRING_SENTINEL,
    KEYRING_SERVICE,
    FileTokenStore,
    KeyringTokenStore,
    get_token_store,
    humanize_keyring_error,
    keyring_fix_commands,
    reset_token_store,
)


INSTANCE_URL = "https://dashboard.gitguardian.com"
TOKEN = "test-token-abc123"


def _fake_backend(module: str, name: str = "fake"):
    """Build a stand-in keyring backend whose class lives in ``module``."""
    cls = type("FakeKeyring", (), {"name": name})
    cls.__module__ = module
    return cls()


class TestKeyringTokenStore:
    def test_store_token(self):
        store = KeyringTokenStore()
        with patch("keyring.set_password") as mock_set:
            store.store_token(INSTANCE_URL, TOKEN)
            mock_set.assert_called_once_with(KEYRING_SERVICE, INSTANCE_URL, TOKEN)

    def test_get_token(self):
        store = KeyringTokenStore()
        with patch("keyring.get_password", return_value=TOKEN) as mock_get:
            result = store.get_token(INSTANCE_URL)
            mock_get.assert_called_once_with(KEYRING_SERVICE, INSTANCE_URL)
            assert result == TOKEN

    def test_get_token_not_found(self):
        store = KeyringTokenStore()
        with patch("keyring.get_password", return_value=None):
            result = store.get_token(INSTANCE_URL)
            assert result is None

    def test_delete_token(self):
        store = KeyringTokenStore()
        with patch("keyring.delete_password") as mock_delete:
            store.delete_token(INSTANCE_URL)
            mock_delete.assert_called_once_with(KEYRING_SERVICE, INSTANCE_URL)

    def test_delete_token_not_found(self):
        import keyring.errors

        store = KeyringTokenStore()
        with patch(
            "keyring.delete_password",
            side_effect=keyring.errors.PasswordDeleteError("not found"),
        ):
            # Should not raise
            store.delete_token(INSTANCE_URL)

    def test_is_available_true(self):
        store = KeyringTokenStore()
        mock_keyring = MagicMock()
        with (
            patch("keyring.get_keyring", return_value=mock_keyring),
            patch("keyring.set_password") as mock_set,
            patch("keyring.get_password", return_value="test") as mock_get,
            patch("keyring.delete_password") as mock_delete,
        ):
            assert store.is_available() is True
            # Verify the probe cycle ran
            mock_set.assert_called_once()
            mock_get.assert_called_once()
            mock_delete.assert_called_once()

    def test_is_available_false_fail_backend(self):
        import keyring.backends.fail

        store = KeyringTokenStore()
        fail_keyring = keyring.backends.fail.Keyring()
        with patch("keyring.get_keyring", return_value=fail_keyring):
            assert store.is_available() is False

    def test_is_available_false_probe_fails(self):
        store = KeyringTokenStore()
        mock_keyring = MagicMock()
        with (
            patch("keyring.get_keyring", return_value=mock_keyring),
            patch("keyring.set_password"),
            patch("keyring.get_password", return_value="wrong"),
            patch("keyring.delete_password"),
        ):
            assert store.is_available() is False

    def test_is_available_false_on_exception(self):
        store = KeyringTokenStore()
        with patch("keyring.get_keyring", side_effect=RuntimeError("broken")):
            assert store.is_available() is False

    def test_is_reachable_true_and_read_only(self):
        store = KeyringTokenStore()
        with (
            patch("keyring.get_keyring", return_value=MagicMock()),
            patch("keyring.get_password", return_value=None) as mock_get,
            patch("keyring.set_password") as mock_set,
            patch("keyring.delete_password") as mock_delete,
        ):
            assert store.is_reachable() is True
            # The reachability probe must never write to the store
            mock_get.assert_called_once()
            mock_set.assert_not_called()
            mock_delete.assert_not_called()

    def test_is_reachable_false_fail_backend(self):
        import keyring.backends.fail

        store = KeyringTokenStore()
        fail_keyring = keyring.backends.fail.Keyring()
        with patch("keyring.get_keyring", return_value=fail_keyring):
            assert store.is_reachable() is False

    def test_is_reachable_false_on_read_error(self):
        store = KeyringTokenStore()
        with (
            patch("keyring.get_keyring", return_value=MagicMock()),
            patch("keyring.get_password", side_effect=RuntimeError("no dbus")),
        ):
            assert store.is_reachable() is False

    @pytest.mark.parametrize(
        ("module", "expected"),
        (
            ("keyring.backends.macOS", "macOS Keychain"),
            ("keyring.backends.Windows", "Windows Credential Locker"),
            ("keyring.backends.SecretService", "Linux Secret Service"),
            ("keyring.backends.kwallet", "KWallet"),
        ),
    )
    def test_backend_name_known_backends(self, module, expected):
        backend = _fake_backend(module)
        with patch("keyring.get_keyring", return_value=backend):
            assert KeyringTokenStore().backend_name == expected

    def test_backend_name_unknown_falls_back_to_backend_name(self):
        backend = _fake_backend("some.third.party", name="Custom Vault")
        with patch("keyring.get_keyring", return_value=backend):
            assert KeyringTokenStore().backend_name == "Custom Vault"

    def test_backend_name_generic_fallback_on_error(self):
        with patch("keyring.get_keyring", side_effect=RuntimeError("boom")):
            assert KeyringTokenStore().backend_name == "OS credential store"


class TestKeyringFixCommands:
    def test_macos_keychain_uses_security_command(self):
        backend = _fake_backend("keyring.backends.macOS")
        with patch("keyring.get_keyring", return_value=backend):
            commands = keyring_fix_commands(INSTANCE_URL)
        assert commands == [
            f"security delete-generic-password -s {KEYRING_SERVICE} "
            f"-a '{INSTANCE_URL}'",
            "ggshield auth login",
        ]

    @pytest.mark.parametrize(
        "module",
        (
            "keyring.backends.Windows",
            "keyring.backends.SecretService",
            # A custom backend, even on macOS, must not get Keychain advice
            "some.third.party",
        ),
    )
    def test_other_backends_only_relogin(self, module):
        backend = _fake_backend(module)
        with patch("keyring.get_keyring", return_value=backend):
            assert keyring_fix_commands(INSTANCE_URL) == ["ggshield auth login"]

    def test_backend_error_only_relogin(self):
        with patch("keyring.get_keyring", side_effect=RuntimeError("boom")):
            assert keyring_fix_commands(INSTANCE_URL) == ["ggshield auth login"]


class TestHumanizeKeyringError:
    def test_translates_known_macos_code(self):
        raw = "Can't store password on keychain: (-25244, 'Unknown Error')"
        msg = humanize_keyring_error(raw)
        assert "different ggshield binary" in msg
        # Raw error is preserved for support
        assert "-25244" in msg

    def test_passthrough_for_unknown_error(self):
        raw = "some other backend failure"
        assert humanize_keyring_error(raw) == raw


class TestFileTokenStore:
    def test_store_token_is_noop(self):
        store = FileTokenStore()
        store.store_token(INSTANCE_URL, TOKEN)  # should not raise

    def test_get_token_returns_none(self):
        store = FileTokenStore()
        assert store.get_token(INSTANCE_URL) is None

    def test_delete_token_is_noop(self):
        store = FileTokenStore()
        store.delete_token(INSTANCE_URL)  # should not raise

    def test_is_available(self):
        store = FileTokenStore()
        assert store.is_available() is True


class TestGetTokenStore:
    @pytest.fixture(autouse=True)
    def _reset(self):
        reset_token_store()
        yield
        reset_token_store()

    def test_returns_keyring_when_available(self, monkeypatch):
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)
        mock_keyring = MagicMock()
        with (
            patch("keyring.get_keyring", return_value=mock_keyring),
            patch("keyring.set_password"),
            patch("keyring.get_password", return_value="test"),
            patch("keyring.delete_password"),
        ):
            store = get_token_store()
            assert isinstance(store, KeyringTokenStore)

    def test_returns_file_store_when_keyring_unavailable(self, monkeypatch):
        import keyring.backends.fail

        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)
        fail_keyring = keyring.backends.fail.Keyring()
        with patch("keyring.get_keyring", return_value=fail_keyring):
            store = get_token_store()
            assert isinstance(store, FileTokenStore)

    @pytest.mark.parametrize("value", ("1", "true", "yes", "TRUE", "Yes"))
    def test_env_var_disables_keyring(self, monkeypatch, value):
        monkeypatch.setenv("GGSHIELD_NO_KEYRING", value)
        store = get_token_store()
        assert isinstance(store, FileTokenStore)

    def test_caches_result(self, monkeypatch):
        monkeypatch.setenv("GGSHIELD_NO_KEYRING", "1")
        store1 = get_token_store()
        store2 = get_token_store()
        assert store1 is store2


class TestUsesExternalStorage:
    def test_keyring_store_uses_external_storage(self):
        assert KeyringTokenStore().uses_external_storage is True

    def test_file_store_does_not_use_external_storage(self):
        assert FileTokenStore().uses_external_storage is False


class TestKeyRingSentinel:
    def test_sentinel_is_not_a_valid_token(self):
        assert KEYRING_SENTINEL == "__KEYRING__"
