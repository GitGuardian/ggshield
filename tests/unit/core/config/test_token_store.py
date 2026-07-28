import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from ggshield.core.config.token_store import (
    KEYRING_SENTINEL,
    KEYRING_SERVICE,
    FileTokenStore,
    KeyringTokenStore,
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


class TestKeyringConcurrency:
    """macOS securityd fails most concurrent reads of the login Keychain, which
    made hook fan-outs (parallel agents/sub-agents) lose scans to spurious auth
    errors. get_token must serialize keychain access across processes/threads."""

    def test_get_token_is_serialized(self, monkeypatch, tmp_path):
        monkeypatch.setenv("GG_CACHE_DIR", str(tmp_path))
        store = KeyringTokenStore()

        state = {"active": 0, "max": 0}
        guard = threading.Lock()

        def fake_get(service, url):
            with guard:
                state["active"] += 1
                state["max"] = max(state["max"], state["active"])
            time.sleep(0.02)  # widen the window an unserialized read would overlap in
            with guard:
                state["active"] -= 1
            return TOKEN

        results = []

        def worker():
            results.append(store.get_token(INSTANCE_URL))

        with patch("keyring.get_password", side_effect=fake_get):
            threads = [threading.Thread(target=worker) for _ in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        assert results == [TOKEN] * 20
        # The advisory lock let only one read touch the keychain at a time.
        assert state["max"] == 1
