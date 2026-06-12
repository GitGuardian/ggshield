from unittest.mock import MagicMock, patch

import pytest

from ggshield.core.config.token_store import (
    KEYRING_SENTINEL,
    KEYRING_SERVICE,
    FileTokenStore,
    KeyringTokenStore,
    _keyring_probe,
    get_token_store,
    reset_token_store,
)


INSTANCE_URL = "https://dashboard.gitguardian.com"
TOKEN = "test-token-abc123"


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

    def _make_process(self, exitcode=0, alive=False):
        p = MagicMock()
        p.exitcode = exitcode
        p.is_alive.return_value = alive
        return p

    def test_is_available_true(self):
        store = KeyringTokenStore()
        with patch("multiprocessing.Process", return_value=self._make_process(0)):
            assert store.is_available() is True

    def test_is_available_false_fail_backend(self):
        store = KeyringTokenStore()
        with patch("multiprocessing.Process", return_value=self._make_process(2)):
            assert store.is_available() is False

    def test_is_available_false_probe_fails(self):
        store = KeyringTokenStore()
        with patch("multiprocessing.Process", return_value=self._make_process(3)):
            assert store.is_available() is False

    def test_is_available_false_on_segfault(self):
        store = KeyringTokenStore()
        # SIGSEGV → exit code -11 / 139
        with patch("multiprocessing.Process", return_value=self._make_process(139)):
            assert store.is_available() is False

    def test_is_available_false_on_timeout(self):
        store = KeyringTokenStore()
        with patch(
            "multiprocessing.Process", return_value=self._make_process(None, alive=True)
        ):
            assert store.is_available() is False

    def test_is_available_false_on_exception(self):
        store = KeyringTokenStore()
        with patch("multiprocessing.Process", side_effect=Exception("broken")):
            assert store.is_available() is False


class TestKeyringProbe:
    """Tests for the _keyring_probe function itself (runs in a child process)."""

    def test_probe_succeeds(self):
        with (
            patch("keyring.get_keyring", return_value=MagicMock()),
            patch("keyring.set_password"),
            patch("keyring.get_password", return_value="test"),
            patch("keyring.delete_password"),
            pytest.raises(SystemExit) as exc_info,
        ):
            _keyring_probe()
        assert exc_info.value.code == 0

    def test_probe_fail_backend(self):
        import keyring.backends.fail

        with (
            patch("keyring.get_keyring", return_value=keyring.backends.fail.Keyring()),
            pytest.raises(SystemExit) as exc_info,
        ):
            _keyring_probe()
        assert exc_info.value.code == 2

    def test_probe_mismatch(self):
        with (
            patch("keyring.get_keyring", return_value=MagicMock()),
            patch("keyring.set_password"),
            patch("keyring.get_password", return_value="wrong"),
            patch("keyring.delete_password"),
            pytest.raises(SystemExit) as exc_info,
        ):
            _keyring_probe()
        assert exc_info.value.code == 3

    def test_probe_delete_error_is_ignored(self):
        with (
            patch("keyring.get_keyring", return_value=MagicMock()),
            patch("keyring.set_password"),
            patch("keyring.get_password", return_value="test"),
            patch("keyring.delete_password", side_effect=Exception("cleanup failed")),
            pytest.raises(SystemExit) as exc_info,
        ):
            _keyring_probe()
        assert exc_info.value.code == 0


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
        ok = MagicMock()
        ok.exitcode = 0
        ok.is_alive.return_value = False
        with patch("multiprocessing.Process", return_value=ok):
            store = get_token_store()
            assert isinstance(store, KeyringTokenStore)

    def test_returns_file_store_when_keyring_unavailable(self, monkeypatch):
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)
        fail = MagicMock()
        fail.exitcode = 2
        fail.is_alive.return_value = False
        with patch("multiprocessing.Process", return_value=fail):
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
