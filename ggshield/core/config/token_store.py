import logging
from abc import ABC, abstractmethod
from typing import List, Optional

import keyring
import keyring.backends.fail
import keyring.errors

from ggshield.utils.os import getenv_bool


logger = logging.getLogger(__name__)

KEYRING_SERVICE = "ggshield"
KEYRING_SENTINEL = "__KEYRING__"
KEYRING_PROBE_KEY = "__ggshield_probe__"


def _uses_macos_keychain() -> bool:
    """Whether the active keyring backend is the macOS Keychain. Derived from
    the backend rather than the OS, so a custom backend on macOS does not get
    Keychain-specific advice."""
    try:
        backend = keyring.get_keyring()
    except Exception:
        return False
    return type(backend).__module__.startswith("keyring.backends.macOS")


def keyring_fix_commands(instance_url: str) -> List[str]:
    """Return the shell commands the user can run to recover from a credential
    store conflict for ``instance_url``.

    On the macOS Keychain the most common cause is a stale entry whose ACL is
    tied to a previous binary path (e.g. after a ``mise``/``asdf`` reshim, a
    ``pyenv``/``pipx`` reinstall or a Homebrew upgrade). The new binary then
    gets ``-25244`` (``errSecInvalidOwnerEdit``) when overwriting the entry, so
    we point the user at ``security`` to delete it first.
    """
    if _uses_macos_keychain():
        return [
            f"security delete-generic-password -s {KEYRING_SERVICE} "
            f"-a '{instance_url}'",
            "ggshield auth login",
        ]
    return ["ggshield auth login"]


def humanize_keyring_error(error: str) -> str:
    """Translate a cryptic credential-store error into plain language, keeping
    the raw error for support. Falls back to the raw error when unrecognized."""
    if "-25244" in error:
        return (
            "the credential-store entry is owned by a different ggshield binary. "
            "This typically happens after ggshield is updated or reinstalled and "
            "its path changes (Homebrew, mise, asdf, pyenv, pipx, ...). "
            f"(raw error: {error})"
        )
    return error


class TokenStore(ABC):
    """Abstract base class for token storage backends."""

    @property
    @abstractmethod
    def uses_external_storage(self) -> bool:
        """Whether tokens are stored externally and should be replaced
        with sentinels in the YAML config file."""
        ...

    @property
    def backend_name(self) -> str:
        """Human-readable name of the storage backend, for user messages."""
        return "credential store"

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

    @property
    def backend_name(self) -> str:
        """Human-readable name of the credential store actually in use.

        Derived from the active ``keyring`` backend rather than the OS, so it
        stays accurate on setups where they differ (e.g. KDE/KWallet on Linux).
        Falls back to the backend's own name, then to a generic label.
        """
        try:
            backend = keyring.get_keyring()
        except Exception:
            return "OS credential store"
        module = type(backend).__module__
        friendly = {
            "keyring.backends.macOS": "macOS Keychain",
            "keyring.backends.Windows": "Windows Credential Locker",
            "keyring.backends.SecretService": "Linux Secret Service",
            "keyring.backends.kwallet": "KWallet",
        }
        for prefix, label in friendly.items():
            if module.startswith(prefix):
                return label
        return getattr(backend, "name", None) or "OS credential store"

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
        """Check if keyring is usable by probing with a test key."""
        try:
            kr = keyring.get_keyring()
            if isinstance(kr, keyring.backends.fail.Keyring):
                return False
            # Probe the backend to verify it actually works (e.g. a
            # ChainerBackend may pass the isinstance check but still fail).
            keyring.set_password(KEYRING_SERVICE, KEYRING_PROBE_KEY, "test")
            val = keyring.get_password(KEYRING_SERVICE, KEYRING_PROBE_KEY)
            try:
                keyring.delete_password(KEYRING_SERVICE, KEYRING_PROBE_KEY)
            except Exception:
                logger.debug("Failed to clean up keyring probe key")
            return val == "test"
        except Exception:
            return False

    def is_reachable(self) -> bool:
        """Read-only check that the credential store answers.

        Unlike :meth:`is_available`, this never writes to the store, so
        diagnostics (`ggshield auth status`) can call it without side effects.
        It only proves the backend answers reads, which is what commands need
        at runtime; write failures are surfaced at save time instead.
        """
        try:
            kr = keyring.get_keyring()
            if isinstance(kr, keyring.backends.fail.Keyring):
                return False
            keyring.get_password(KEYRING_SERVICE, KEYRING_PROBE_KEY)
        except Exception:
            return False
        return True


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
