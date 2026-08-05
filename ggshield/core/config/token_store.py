import contextlib
import logging
from abc import ABC, abstractmethod
from typing import Iterator, Optional

import filelock
import keyring
import keyring.backends.fail
import keyring.errors

from ggshield.core.dirs import get_cache_dir
from ggshield.utils.os import getenv_bool


logger = logging.getLogger(__name__)

KEYRING_SERVICE = "ggshield"
KEYRING_SENTINEL = "__KEYRING__"

# Concurrent reads of the OS credential store can fail (macOS securityd rejects
# most simultaneous reads of the login Keychain), so fetching the token in
# parallel loses reads to spurious auth errors. Serialize keyring access with a
# file lock, held only for the keychain call, never the network scan.
_KEYRING_LOCK_TIMEOUT = 10.0


@contextlib.contextmanager
def _keyring_lock() -> Iterator[None]:
    """Serialize keyring access across ggshield processes.

    Proceeds unlocked if the lock can't be acquired within the timeout, so a
    stuck holder can never hang a caller.
    """
    cache_dir = get_cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)
    lock = filelock.FileLock(
        str(cache_dir / "keyring.lock"), timeout=_KEYRING_LOCK_TIMEOUT
    )
    try:
        lock.acquire()
    except filelock.Timeout:
        yield
        return
    try:
        yield
    finally:
        lock.release()


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
        with _keyring_lock():
            keyring.set_password(KEYRING_SERVICE, instance_url, token)

    def get_token(self, instance_url: str) -> Optional[str]:
        with _keyring_lock():
            return keyring.get_password(KEYRING_SERVICE, instance_url)

    def delete_token(self, instance_url: str) -> None:
        with _keyring_lock():
            try:
                keyring.delete_password(KEYRING_SERVICE, instance_url)
            except keyring.errors.PasswordDeleteError:
                logger.debug("No keyring entry to delete for instance %s", instance_url)

    def is_available(self) -> bool:
        """Check if keyring is usable, by probing it with a read.

        The probe must never write: on macOS, set_password() pops a blocking
        modal ("A keychain cannot be found to store ...") when the Security
        framework can't resolve a writable keychain, which froze hooks and
        flooded users with dialogs. Reading a key that was never stored
        returns None on a working backend and raises on a broken one (e.g. a
        ChainerBackend that passes the isinstance check above), which is all
        the signal we need. This also matches what the hot path does: reading
        a token. Writes are only done by the interactive `auth login`, where a
        dialog is acceptable and a failure already falls back to the config
        file.
        """
        try:
            kr = keyring.get_keyring()
            if isinstance(kr, keyring.backends.fail.Keyring):
                return False
            # Hold the lock across the probe so it doesn't race the token
            # reads of concurrent processes.
            with _keyring_lock():
                keyring.get_password(KEYRING_SERVICE, "__ggshield_probe__")
            return True
        except Exception:
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
