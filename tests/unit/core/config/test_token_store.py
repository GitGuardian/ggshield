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
    FileKeystore,
    KeystoreError,
    KeystoreFailure,
    OSKeystore,
    _macos_trusted_binaries,
    get_keystore,
    reset_keystore,
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
        store = OSKeystore()
        with patch("keyring.set_password") as mock_set:
            store.store_token(INSTANCE_URL, TOKEN)
            mock_set.assert_called_once_with(KEYRING_SERVICE, INSTANCE_URL, TOKEN)

    def test_store_token_raises_when_nothing_is_written(self, monkeypatch):
        """GIVEN a keystore that refuses the write WHEN a token is stored THEN a
        DENIED KeystoreError carries the reason"""
        import keyring.errors

        monkeypatch.setattr(sys, "platform", "linux")
        with patch(
            "keyring.set_password",
            side_effect=keyring.errors.PasswordSetError("Keychain is locked"),
        ):
            with pytest.raises(KeystoreError) as exc_info:
                OSKeystore().store_token(INSTANCE_URL, TOKEN)

        assert exc_info.value.failure == KeystoreFailure.DENIED
        assert exc_info.value.detail == "Keychain is locked"

    def test_read_token(self):
        store = OSKeystore()
        with patch("keyring.get_password", return_value=TOKEN) as mock_get:
            result = store.read_token(INSTANCE_URL)
            mock_get.assert_called_once_with(KEYRING_SERVICE, INSTANCE_URL)
            assert result == TOKEN

    def test_read_token_not_found(self):
        """GIVEN no item for the instance WHEN the token is read THEN NOT_FOUND
        is raised"""
        store = OSKeystore()
        with patch("keyring.get_password", return_value=None):
            with pytest.raises(KeystoreError) as exc_info:
                store.read_token(INSTANCE_URL)

        assert exc_info.value.failure == KeystoreFailure.NOT_FOUND

    def test_read_token_denied(self):
        """GIVEN a keystore that refuses the read WHEN the token is read THEN
        DENIED is raised with the reason from the keystore"""
        import keyring.errors

        store = OSKeystore()
        with patch(
            "keyring.get_password",
            side_effect=keyring.errors.KeyringLocked(
                "User interaction is not allowed."
            ),
        ):
            with pytest.raises(KeystoreError) as exc_info:
                store.read_token(INSTANCE_URL)

        assert exc_info.value.failure == KeystoreFailure.DENIED
        assert exc_info.value.detail == "User interaction is not allowed."

    def test_delete_token(self):
        store = OSKeystore()
        with patch("keyring.delete_password") as mock_delete:
            store.delete_token(INSTANCE_URL)
            mock_delete.assert_called_once_with(KEYRING_SERVICE, INSTANCE_URL)

    def test_delete_token_not_found(self):
        import keyring.errors

        store = OSKeystore()
        with patch(
            "keyring.delete_password",
            side_effect=keyring.errors.PasswordDeleteError("not found"),
        ):
            # Should not raise
            store.delete_token(INSTANCE_URL)

    def test_is_available_true(self):
        """GIVEN a working backend WHEN probing THEN a read of an unknown key
        returning None means available"""
        store = OSKeystore()
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
        store = OSKeystore()
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

        store = OSKeystore()
        fail_keyring = keyring.backends.fail.Keyring()
        with patch("keyring.get_keyring", return_value=fail_keyring):
            assert store.is_available() is False

    def test_is_available_false_probe_fails(self):
        """GIVEN a backend whose get_password raises THEN it is not available"""
        store = OSKeystore()
        with (
            patch("keyring.get_keyring", return_value=MagicMock()),
            patch("keyring.get_password", side_effect=RuntimeError("no keychain")),
        ):
            assert store.is_available() is False

    def test_is_available_true_with_stale_probe_entry(self):
        """GIVEN an old ggshield left a probe entry in the keychain THEN the
        backend is still reported available (we never delete it: that's a write)"""
        store = OSKeystore()
        with (
            patch("keyring.get_keyring", return_value=MagicMock()),
            patch("keyring.get_password", return_value="test"),
            patch("keyring.delete_password") as mock_delete,
        ):
            assert store.is_available() is True
            mock_delete.assert_not_called()

    def test_is_available_false_on_exception(self):
        store = OSKeystore()
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
            OSKeystore().store_token(INSTANCE_URL, TOKEN)

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
        """GIVEN the Security framework refuses the access list WHEN a token is
        stored THEN a plain keystore write follows, with a warning about the
        missing access list"""
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(token_store, "_writes_to_the_apple_keychain", lambda: True)
        with (
            patch(
                "ggshield.core.config.token_store._macos_store_token",
                side_effect=RuntimeError("no such symbol"),
            ),
            patch("keyring.set_password") as mock_set,
            patch("ggshield.core.ui.display_warning") as mock_warning,
        ):
            OSKeystore().store_token(INSTANCE_URL, TOKEN)

        mock_set.assert_called_once_with(KEYRING_SERVICE, INSTANCE_URL, TOKEN)
        mock_warning.assert_called_once()
        assert "no such symbol" in mock_warning.call_args.args[0]

    def test_store_token_does_not_claim_success_when_nothing_is_written(
        self, monkeypatch
    ):
        """GIVEN a locked Keychain, where the access-list write and the plain write
        both fail WHEN a token is stored THEN an error is raised, and no warning
        says the token was stored"""
        monkeypatch.setattr(sys, "platform", "darwin")
        monkeypatch.setattr(token_store, "_writes_to_the_apple_keychain", lambda: True)
        with (
            patch(
                "ggshield.core.config.token_store._macos_store_token",
                side_effect=RuntimeError("User interaction is not allowed."),
            ),
            patch(
                "keyring.set_password",
                side_effect=RuntimeError("User interaction is not allowed."),
            ),
            patch("ggshield.core.ui.display_warning") as mock_warning,
        ):
            with pytest.raises(KeystoreError):
                OSKeystore().store_token(INSTANCE_URL, TOKEN)

        mock_warning.assert_not_called()

    def test_store_token_is_unchanged_off_macos(self, monkeypatch):
        """GIVEN Linux or Windows WHEN storing a token THEN the macOS path is
        not taken"""
        monkeypatch.setattr(sys, "platform", "linux")
        with (
            patch("ggshield.core.config.token_store._macos_store_token") as mock_acl,
            patch("keyring.set_password") as mock_set,
        ):
            OSKeystore().store_token(INSTANCE_URL, TOKEN)

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
            OSKeystore().store_token(INSTANCE_URL, TOKEN)

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
        store = FileKeystore()
        store.store_token(INSTANCE_URL, TOKEN)  # should not raise

    def test_read_token_raises_why_the_store_is_not_used(self):
        """GIVEN a file keystore chosen because the OS keystore is unreachable
        WHEN a stored token is read THEN the reason for that choice is raised"""
        store = FileKeystore(KeystoreFailure.UNAVAILABLE, "no D-Bus session")
        with pytest.raises(KeystoreError) as exc_info:
            store.read_token(INSTANCE_URL)

        assert exc_info.value.failure == KeystoreFailure.UNAVAILABLE
        assert exc_info.value.detail == "no D-Bus session"

    def test_delete_token_is_noop(self):
        store = FileKeystore()
        store.delete_token(INSTANCE_URL)  # should not raise

    def test_is_available(self):
        store = FileKeystore()
        assert store.is_available() is True


class TestGetTokenStore:
    @pytest.fixture(autouse=True)
    def _reset(self):
        reset_keystore()
        yield
        reset_keystore()

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
            store = get_keystore()
            assert isinstance(store, OSKeystore)

    def test_returns_file_store_when_keyring_unavailable(self, monkeypatch):
        import keyring.backends.fail

        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)
        fail_keyring = keyring.backends.fail.Keyring()
        with patch("keyring.get_keyring", return_value=fail_keyring):
            store = get_keystore()
            assert isinstance(store, FileKeystore)
            assert store.failure == KeystoreFailure.UNAVAILABLE
            assert store.detail == "no credential store backend is available"

    def test_returns_file_store_when_probe_raises(self, monkeypatch):
        """GIVEN a keystore that cannot be read WHEN a keystore is selected THEN
        the file keystore is used, and the reason from the availability check
        is kept"""
        monkeypatch.delenv("GGSHIELD_NO_KEYRING", raising=False)
        with (
            patch("keyring.get_keyring", return_value=MagicMock()),
            patch("keyring.get_password", side_effect=RuntimeError("no keychain")),
        ):
            store = get_keystore()
            assert isinstance(store, FileKeystore)
            assert store.failure == KeystoreFailure.UNAVAILABLE
            assert store.detail == "no keychain"

    @pytest.mark.parametrize("value", ("1", "true", "yes", "TRUE", "Yes"))
    def test_env_var_disables_keyring(self, monkeypatch, value):
        monkeypatch.setenv("GGSHIELD_NO_KEYRING", value)
        store = get_keystore()
        assert isinstance(store, FileKeystore)
        assert store.failure == KeystoreFailure.DISABLED

    def test_caches_result(self, monkeypatch):
        monkeypatch.setenv("GGSHIELD_NO_KEYRING", "1")
        store1 = get_keystore()
        store2 = get_keystore()
        assert store1 is store2


class TestUsesExternalStorage:
    def test_keyring_store_uses_external_storage(self):
        assert OSKeystore().uses_external_storage is True

    def test_file_store_does_not_use_external_storage(self):
        assert FileKeystore().uses_external_storage is False


class TestKeyRingSentinel:
    def test_sentinel_is_not_a_valid_token(self):
        assert KEYRING_SENTINEL == "__KEYRING__"


class TestKeyringConcurrency:
    """macOS rejects most concurrent reads of the login Keychain. Hooks that
    run in parallel then failed to authenticate. read_token therefore
    serializes keystore access across processes and threads."""

    def test_read_token_is_serialized(self, monkeypatch, tmp_path):
        monkeypatch.setenv("GG_CACHE_DIR", str(tmp_path))
        store = OSKeystore()

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
            results.append(store.read_token(INSTANCE_URL))

        with patch("keyring.get_password", side_effect=fake_get):
            threads = [threading.Thread(target=worker) for _ in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        assert results == [TOKEN] * 20
        # The advisory lock let only one read touch the keychain at a time.
        assert state["max"] == 1
