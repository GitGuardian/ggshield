import logging
import multiprocessing
import sys
from abc import ABC, abstractmethod
from typing import Optional

import keyring
import keyring.backends.fail
import keyring.errors

from ggshield.utils.os import getenv_bool


logger = logging.getLogger(__name__)

KEYRING_SERVICE = "ggshield"
KEYRING_SENTINEL = "__KEYRING__"


def _keyring_probe() -> None:
    """Probe run in a child process to test whether keyring actually works.

    Must stay at module level so multiprocessing can pickle it for spawn-based
    starts (e.g. PyInstaller frozen builds).
    Exit codes: 0 = ok, 2 = fail backend, 3 = round-trip mismatch.
    """
    kr = keyring.get_keyring()
    if isinstance(kr, keyring.backends.fail.Keyring):
        sys.exit(2)
    keyring.set_password(KEYRING_SERVICE, "__ggshield_probe__", "test")
    val = keyring.get_password(KEYRING_SERVICE, "__ggshield_probe__")
    try:
        keyring.delete_password(KEYRING_SERVICE, "__ggshield_probe__")
    except Exception:
        pass
    sys.exit(0 if val == "test" else 3)


class TokenStore(ABC):
    """Abstract base class for token storage backends."""

    @property
    @abstractmethod
    def uses_external_storage(self) -> bool:
        """Whether tokens are stored externally and should be replaced
        with sentinels in the YAML config file."""
        ...

    @abstractmethod
    def store_token(self, instance_url: str, token: str) -> None: ...

    @abstractmethod
    def get_token(self, instance_url: str) -> Optional[str]: ...

    @abstractmethod
    def delete_token(self, instance_url: str) -> None: ...

    @abstractmethod
    def is_available(self) -> bool: ...


class KeyringTokenStore(TokenStore):
    """Stores tokens in the OS credential store via the keyring library."""

    @property
    def uses_external_storage(self) -> bool:
        return True

    def store_token(self, instance_url: str, token: str) -> None:
        keyring.set_password(KEYRING_SERVICE, instance_url, token)

    def get_token(self, instance_url: str) -> Optional[str]:
        return keyring.get_password(KEYRING_SERVICE, instance_url)

    def delete_token(self, instance_url: str) -> None:
        try:
            keyring.delete_password(KEYRING_SERVICE, instance_url)
        except keyring.errors.PasswordDeleteError:
            logger.debug("No keyring entry to delete for instance %s", instance_url)

    def is_available(self) -> bool:
        """Check if keyring is usable by probing with a test key.

        The probe runs in a child process so that a segfault in a native
        backend (e.g. libsecret or KWallet) doesn't crash the main process.
        multiprocessing.Process is used instead of subprocess so that frozen
        (PyInstaller) builds work correctly — sys.executable would be the
        ggshield binary there, not a Python interpreter.
        """
        try:
            process = multiprocessing.Process(target=_keyring_probe)
            process.start()
            process.join(timeout=10)
            if process.is_alive():
                process.kill()
                process.join()
                logger.debug("Keyring probe timed out")
                return False
            if process.exitcode != 0:
                logger.debug(
                    "Keyring probe process exited with code %d", process.exitcode
                )
            return process.exitcode == 0
        except Exception:
            logger.debug("Keyring probe failed", exc_info=True)
            return False


class FileTokenStore(TokenStore):
    """Fallback: tokens remain in the YAML config file."""

    @property
    def uses_external_storage(self) -> bool:
        return False

    def store_token(self, instance_url: str, token: str) -> None:
        pass

    def get_token(self, instance_url: str) -> Optional[str]:
        return None

    def delete_token(self, instance_url: str) -> None:
        pass

    def is_available(self) -> bool:
        return True


_token_store: Optional[TokenStore] = None


def get_token_store() -> TokenStore:
    """Return the active token store, selecting keyring when available."""
    global _token_store
    if _token_store is not None:
        return _token_store

    if getenv_bool("GGSHIELD_NO_KEYRING", default=False):
        logger.debug("Keyring disabled via GGSHIELD_NO_KEYRING env var")
        _token_store = FileTokenStore()
        return _token_store

    store = KeyringTokenStore()
    if store.is_available():
        _token_store = store
    else:
        logger.debug(
            "Keyring is not available, falling back to file-based token storage"
        )
        _token_store = FileTokenStore()
    return _token_store


def reset_token_store() -> None:
    """Reset the cached token store. Used in tests."""
    global _token_store
    _token_store = None
