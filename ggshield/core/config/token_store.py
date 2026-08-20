import contextlib
import logging
import os
import sys
from abc import ABC, abstractmethod
from typing import Iterator, List, Optional

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


# Names of the sibling binaries that must be able to read the token without a
# Keychain prompt: the native dispatcher and the Python entry point.
_MACOS_TRUSTED_BINARY_NAMES = ("ggshield", "ggshield-py")


def _macos_trusted_binaries() -> List[str]:
    """Existing paths of the ggshield binaries allowed to read the token.

    The writer itself is part of the list: once an item carries a custom
    SecAccess its creator is no longer trusted implicitly, so leaving it out
    would make ggshield prompt for the token it just wrote.
    """
    roots = [sys.executable]
    argv0 = sys.argv[0] if sys.argv else ""
    if os.sep in argv0:
        roots.append(os.path.abspath(argv0))

    candidates = list(roots)
    for root in roots:
        directory = os.path.dirname(root)
        candidates += [
            os.path.join(directory, name) for name in _MACOS_TRUSTED_BINARY_NAMES
        ]

    paths: List[str] = []
    for candidate in candidates:
        if not candidate or not os.path.exists(candidate):
            continue
        real = os.path.realpath(candidate)
        if real not in paths:
            paths.append(real)
    return paths


def _writes_to_the_apple_keychain() -> bool:
    """Whether the configured keyring backend is the Apple Keychain itself.

    `_macos_store_token` bypasses keyring and talks to the Keychain directly,
    while `get_token`/`delete_token` go through the configured backend. With
    PYTHON_KEYRING_BACKEND pointing elsewhere the two disagree: `auth login`
    reports success and nothing can authenticate afterwards, because the token
    was written where nothing reads it.
    """
    try:
        from keyring.backends import macOS

        return isinstance(keyring.get_keyring(), macOS.Keyring)
    except Exception:
        return False


def _macos_store_token(instance_url: str, token: str) -> None:
    """Store the token in the Keychain with an ACL trusting every ggshield binary.

    A Keychain item is only readable by the app that created it, and keyring's
    macOS backend deletes then re-adds the item instead of updating it, so its
    ACL is rebuilt from scratch on every write. `auth login` runs from Python
    while the native hook reads the token: macOS prompts, and clicking "Always
    Allow" is undone by the next login. Creating the item with an explicit
    SecAccess listing all the binaries fixes it for good.

    SecAccessCreate/SecTrustedApplicationCreateFromPath are deprecated but they
    remain the only way to set a per-item ACL.
    """
    import ctypes

    from keyring.backends.macOS import api

    paths = _macos_trusted_binaries()
    logger.debug("Storing token with a Keychain ACL trusting %s", paths)

    # These two Security functions are not part of keyring's bindings, so they
    # carry no argtypes. Without them ctypes passes pointers as 32-bit ints and
    # a truncated CFStringRef segfaults -- which no `except` can catch.
    create_app = api._sec.SecTrustedApplicationCreateFromPath
    create_app.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
    create_app.restype = ctypes.c_int32
    create_access = api._sec.SecAccessCreate
    create_access.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    create_access.restype = ctypes.c_int32

    trusted_apps = (ctypes.c_void_p * len(paths))()
    for index, path in enumerate(paths):
        app = ctypes.c_void_p()
        api.Error.raise_for_status(create_app(path.encode(), ctypes.byref(app)))
        trusted_apps[index] = app

    # kCFTypeArrayCallBacks is a data symbol, not a function: it has to be read
    # with in_dll and passed by address. Reaching for it as an attribute yields a
    # function pointer, which CFArrayCreate dereferences as a callback table --
    # a segfault, which no `except` can catch.
    callbacks = ctypes.c_void_p.in_dll(api._found, "kCFTypeArrayCallBacks")
    create_array = api._found.CFArrayCreate
    create_array.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_long,
        ctypes.c_void_p,
    ]
    create_array.restype = ctypes.c_void_p
    cf_apps = create_array(None, trusted_apps, len(paths), ctypes.byref(callbacks))
    access = ctypes.c_void_p()
    api.Error.raise_for_status(
        create_access(
            api.create_cf(KEYRING_SERVICE),
            ctypes.c_void_p(cf_apps),
            ctypes.byref(access),
        )
    )

    # Same delete + add as keyring: an existing item cannot be given a new ACL.
    with contextlib.suppress(api.NotFound):
        api.delete_generic_password(None, KEYRING_SERVICE, instance_url)

    api.Error.raise_for_status(
        api.SecItemAdd(
            api.create_query(
                kSecClass=api.k_("kSecClassGenericPassword"),
                kSecAttrService=KEYRING_SERVICE,
                kSecAttrAccount=instance_url,
                kSecValueData=token,
                kSecAttrAccess=access,
            ),
            None,
        )
    )


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
            if sys.platform == "darwin" and _writes_to_the_apple_keychain():
                try:
                    _macos_store_token(instance_url, token)
                    return
                except Exception as exc:
                    # Loud on purpose: the token is still stored, but only this
                    # binary can read it without asking. The other one prompts,
                    # and an agent-spawned hook cannot answer a Keychain dialog —
                    # so the symptom is a hook that stops scanning, with the cause
                    # nowhere the user would look.
                    logger.warning(
                        "Could not grant every ggshield binary access to the token "
                        "in the Keychain (%s). The token was stored, but macOS may "
                        "ask for permission again; run 'ggshield api-status' once in "
                        "a terminal to approve it.",
                        exc,
                    )
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
