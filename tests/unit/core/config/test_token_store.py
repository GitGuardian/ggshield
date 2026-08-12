import ctypes
import importlib.metadata
import os
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from ggshield.core.config import token_store
from ggshield.core.config.token_store import (
    KEYRING_SENTINEL,
    KEYRING_SERVICE,
    FileTokenStore,
    KeyringTokenStore,
    _macos_trusted_binaries,
    get_token_store,
    reset_token_store,
)


INSTANCE_URL = "https://dashboard.gitguardian.com"
TOKEN = "test-token-abc123"


class _FakeNotFound(Exception):
    """Stands in for keyring's macOS api.NotFound, which must be suppressible."""


class TestKeyringTokenStore:
    def test_store_token(self, monkeypatch):
        """GIVEN a platform without Keychain ACLs WHEN storing THEN keyring is
        called directly"""
        monkeypatch.setattr(sys, "platform", "linux")
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
        """GIVEN a working backend WHEN probing THEN a read of an unknown key
        returning None means available"""
        store = KeyringTokenStore()
        with (
            patch("keyring.get_keyring", return_value=MagicMock()),
            patch("keyring.get_password", return_value=None) as mock_get,
        ):
            assert store.is_available() is True
            mock_get.assert_called_once()

    def test_is_available_never_writes(self):
        """GIVEN a working backend WHEN probing THEN it must not write.

        Regression guard: probing with set_password pops a blocking modal on
        macOS when no writable keychain can be resolved.
        """
        store = KeyringTokenStore()
        with (
            patch("keyring.get_keyring", return_value=MagicMock()),
            patch("keyring.get_password", return_value=None),
            patch("keyring.set_password") as mock_set,
            patch("keyring.delete_password") as mock_delete,
        ):
            assert store.is_available() is True
            mock_set.assert_not_called()
            mock_delete.assert_not_called()

    def test_is_available_false_fail_backend(self):
        import keyring.backends.fail

        store = KeyringTokenStore()
        fail_keyring = keyring.backends.fail.Keyring()
        with patch("keyring.get_keyring", return_value=fail_keyring):
            assert store.is_available() is False

    def test_is_available_false_probe_fails(self):
        """GIVEN a backend whose get_password raises THEN it is not available"""
        store = KeyringTokenStore()
        with (
            patch("keyring.get_keyring", return_value=MagicMock()),
            patch("keyring.get_password", side_effect=RuntimeError("no keychain")),
        ):
            assert store.is_available() is False

    def test_is_available_true_with_stale_probe_entry(self):
        """GIVEN an old ggshield left a probe entry in the keychain THEN the
        backend is still reported available (we never delete it: that's a write)"""
        store = KeyringTokenStore()
        with (
            patch("keyring.get_keyring", return_value=MagicMock()),
            patch("keyring.get_password", return_value="test"),
            patch("keyring.delete_password") as mock_delete,
        ):
            assert store.is_available() is True
            mock_delete.assert_not_called()

    def test_is_available_false_on_exception(self):
        store = KeyringTokenStore()
        with patch("keyring.get_keyring", side_effect=RuntimeError("broken")):
            assert store.is_available() is False


class TestMacOSKeychainACL:
    """A Keychain item is only readable by the app that created it, and keyring
    re-creates the item on every write. The Python CLI writes the token, the
    native binary reads it, so the item must be created with an ACL trusting
    both -- otherwise macOS prompts again after each `auth login`."""

    @pytest.fixture
    def fake_bin(self, tmp_path, monkeypatch):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        for name in ("python", "ggshield"):
            (bin_dir / name).write_text("")
        # ggshield-py is deliberately absent: it must not be trusted.
        monkeypatch.setattr(sys, "executable", str(bin_dir / "python"))
        monkeypatch.setattr(sys, "argv", ["ggshield"])
        return bin_dir

    def test_trusted_binaries_include_writer_and_existing_siblings(self, fake_bin):
        """GIVEN a bin dir with some ggshield binaries THEN the writer and the
        existing siblings are trusted, the missing ones are skipped"""
        paths = _macos_trusted_binaries()

        assert os.path.realpath(sys.executable) in paths, "the writer must be trusted"
        assert set(paths) == {
            os.path.realpath(str(fake_bin / name)) for name in ("python", "ggshield")
        }

    def test_trusted_binaries_dedupe(self, fake_bin, monkeypatch):
        """GIVEN argv[0] pointing at a binary already found as a sibling THEN
        it is listed once"""
        monkeypatch.setattr(sys, "argv", [str(fake_bin / "ggshield")])

        paths = _macos_trusted_binaries()

        assert len(paths) == len(set(paths))
        assert paths.count(os.path.realpath(str(fake_bin / "ggshield"))) == 1

    def test_store_token_attaches_the_acl(self, fake_bin, monkeypatch):
        """GIVEN macOS WHEN storing a token THEN the item is re-created with a
        kSecAttrAccess built from the trusted binaries"""
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(token_store, "_writes_to_the_apple_keychain", lambda: True)
        fake_api = MagicMock()
        fake_api.NotFound = _FakeNotFound
        fake_api._found.CFArrayCreate.return_value = 1

        with (
            patch("keyring.backends.macOS.api", fake_api, create=True),
            # in_dll needs a real CDLL; the fake api module cannot provide one.
            patch.object(ctypes.c_void_p, "in_dll", return_value=ctypes.c_void_p(1)),
            patch("keyring.set_password") as mock_set,
        ):
            KeyringTokenStore().store_token(INSTANCE_URL, TOKEN)

        # One trusted-app handle per trusted binary, whatever that list holds.
        assert fake_api._sec.SecTrustedApplicationCreateFromPath.call_count == len(
            _macos_trusted_binaries()
        )
        fake_api.delete_generic_password.assert_called_once_with(
            None, KEYRING_SERVICE, INSTANCE_URL
        )
        query_kwargs = fake_api.create_query.call_args.kwargs
        assert query_kwargs["kSecAttrService"] == KEYRING_SERVICE
        assert query_kwargs["kSecAttrAccount"] == INSTANCE_URL
        assert query_kwargs["kSecValueData"] == TOKEN
        assert "kSecAttrAccess" in query_kwargs
        fake_api.SecItemAdd.assert_called_once()
        mock_set.assert_not_called()

    def test_store_token_falls_back_when_acl_fails(self, monkeypatch):
        """GIVEN the Security API refuses WHEN storing a token THEN we fall back
        to a plain keyring write: login must never break over an ACL"""
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(token_store, "_writes_to_the_apple_keychain", lambda: True)
        with (
            patch(
                "ggshield.core.config.token_store._macos_store_token",
                side_effect=RuntimeError("no such symbol"),
            ),
            patch("keyring.set_password") as mock_set,
        ):
            KeyringTokenStore().store_token(INSTANCE_URL, TOKEN)

        mock_set.assert_called_once_with(KEYRING_SERVICE, INSTANCE_URL, TOKEN)

    def test_store_token_is_unchanged_off_macos(self, monkeypatch):
        """GIVEN Linux or Windows WHEN storing a token THEN the macOS path is
        not taken"""
        monkeypatch.setattr(sys, "platform", "linux")
        with (
            patch("ggshield.core.config.token_store._macos_store_token") as mock_acl,
            patch("keyring.set_password") as mock_set,
        ):
            KeyringTokenStore().store_token(INSTANCE_URL, TOKEN)

        mock_acl.assert_not_called()
        mock_set.assert_called_once_with(KEYRING_SERVICE, INSTANCE_URL, TOKEN)

    def test_store_token_follows_the_configured_backend(self, monkeypatch):
        """GIVEN macOS with PYTHON_KEYRING_BACKEND pointing somewhere else WHEN
        storing a token THEN the write goes through keyring, not the Keychain.

        The direct Keychain write is only correct when the Keychain is also what
        get_token reads. Otherwise `auth login` reports success and nothing can
        authenticate afterwards, because the token sits where nothing looks.
        """
        monkeypatch.setattr(sys, "platform", "darwin")
        with (
            patch("keyring.get_keyring", return_value=MagicMock()),
            patch("ggshield.core.config.token_store._macos_store_token") as mock_acl,
            patch("keyring.set_password") as mock_set,
        ):
            KeyringTokenStore().store_token(INSTANCE_URL, TOKEN)

        mock_acl.assert_not_called()
        mock_set.assert_called_once_with(KEYRING_SERVICE, INSTANCE_URL, TOKEN)

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS backend only")
    def test_the_keychain_backend_is_detected(self):
        """GIVEN the macOS Keychain backend, and any other one WHEN each is probed
        THEN only the Keychain takes the ACL path"""
        from keyring.backends import macOS

        with patch("keyring.get_keyring", return_value=macOS.Keyring()):
            assert token_store._writes_to_the_apple_keychain() is True
        with patch("keyring.get_keyring", return_value=MagicMock()):
            assert token_store._writes_to_the_apple_keychain() is False

    def test_keyring_is_new_enough_for_the_keychain_acl(self):
        """GIVEN the installed keyring WHEN its version is checked THEN it is one
        that has `api.create_cf`.

        `_macos_store_token` calls it, and on keyring 24.x -- which the dependency
        range used to allow -- the AttributeError was swallowed by the fallback,
        so the ACL silently never applied and macOS prompted after every login.
        """
        major = int(importlib.metadata.version("keyring").split(".")[0])
        assert major >= 25, "keyring 24.x has create_cfstr, not create_cf"
        if sys.platform == "darwin":
            from keyring.backends.macOS import api

            assert hasattr(api, "create_cf")


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
        with (
            patch("keyring.get_keyring", return_value=MagicMock()),
            patch("keyring.get_password", return_value=None),
            patch(
                "keyring.set_password",
                side_effect=AssertionError("selection must not write"),
            ),
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

    def test_returns_file_store_when_probe_raises(self, monkeypatch):
        """GIVEN a backend that can't be read WHEN selecting a store THEN we
        degrade to the file store instead of crashing"""
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)
        with (
            patch("keyring.get_keyring", return_value=MagicMock()),
            patch("keyring.get_password", side_effect=RuntimeError("no keychain")),
        ):
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
