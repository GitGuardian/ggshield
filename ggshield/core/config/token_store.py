import contextlib
import ctypes
import logging
import os
import sys
from abc import ABC, abstractmethod
from enum import Enum
from typing import Iterator, List, Optional

import filelock
import keyring
import keyring.backends.fail
import keyring.errors

from ggshield.core import ui
from ggshield.core.dirs import get_cache_dir
from ggshield.utils.os import getenv_bool


logger = logging.getLogger(__name__)

KEYRING_SERVICE = "ggshield"
KEYRING_SENTINEL = "__KEYRING__"


def keystore_display_name() -> str:
    if sys.platform == "darwin":
        return "macOS Keychain"
    if sys.platform == "win32":
        return "Windows Credential Manager"
    if sys.platform.startswith("linux"):
        return "Secret Service"
    return "OS credential store"


class KeystoreFailure(Enum):
    DISABLED = "disabled"
    UNAVAILABLE = "unavailable"
    DENIED = "denied"
    NOT_FOUND = "not_found"


class KeystoreError(Exception):
    def __init__(self, failure: KeystoreFailure, detail: str = ""):
        super().__init__(detail or failure.value)
        self.failure = failure
        self.detail = detail

    def read_failure_message(self, instance_url: str) -> str:
        store = keystore_display_name()
        prefix = f"The token for '{instance_url}' is in the {store}"
        if self.failure == KeystoreFailure.DISABLED:
            return (
                f"{prefix}, but GGSHIELD_NO_KEYRING is set. Unset it, or run "
                "`ggshield auth login` to save a new token in the config file."
            )
        if self.failure == KeystoreFailure.UNAVAILABLE:
            return (
                f"{prefix}, but the {store} cannot be reached in this session "
                f"({self.detail}). Run ggshield from a desktop session, or set "
                "GITGUARDIAN_API_KEY."
            )
        if self.failure == KeystoreFailure.NOT_FOUND:
            return (
                f"The token for '{instance_url}' should be in the {store}, but it "
                "is not there. Run `ggshield auth login` to store a new one."
            )
        cause = (
            "The Keychain may be locked, or its item may not trust this ggshield "
            "binary."
            if sys.platform == "darwin"
            else f"The {store} may be locked."
        )
        return (
            f"{prefix}, but ggshield cannot read it in this session "
            f"({self.detail}). {cause} Run `ggshield auth login` in a terminal "
            "to store the token again."
        )

    def write_failure_message(self, instance_url: str, config_path: str) -> str:
        store = keystore_display_name()
        remedy = (
            "To move it to the Keychain, unlock it with `security unlock-keychain` "
            "and run `ggshield auth login` again."
            if sys.platform == "darwin"
            else f"To move it, make the {store} available and run "
            "`ggshield auth login` again."
        )
        return (
            f"Could not store the token for '{instance_url}' in the {store} "
            f"({self.detail}). "
            f"It is saved in clear text in {config_path}. {remedy}"
        )


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


@contextlib.contextmanager
def keychain_prompts_disabled() -> Iterator[None]:
    """Make Keychain reads in this block fail instead of showing a dialog.

    The setting applies to the whole process while the block runs, and the
    previous setting is restored afterwards.
    """
    if sys.platform != "darwin" or not _writes_to_the_apple_keychain():
        yield
        return
    try:
        from keyring.backends.macOS import api

        set_allowed = api._sec.SecKeychainSetUserInteractionAllowed
        set_allowed.argtypes = [ctypes.c_ubyte]
        set_allowed.restype = ctypes.c_int32
        get_allowed = api._sec.SecKeychainGetUserInteractionAllowed
        get_allowed.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
        get_allowed.restype = ctypes.c_int32
        previous = ctypes.c_ubyte(1)
        if get_allowed(ctypes.byref(previous)) != 0 or set_allowed(0) != 0:
            raise OSError("the Security framework refused the change")
    except Exception:
        logger.debug("Could not disable Keychain user interaction", exc_info=True)
        yield
        return
    try:
        yield
    finally:
        set_allowed(previous.value)


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


class Keystore(ABC):
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
    def read_token(self, instance_url: str) -> str: ...

    @abstractmethod
    def delete_token(self, instance_url: str) -> None: ...

    @abstractmethod
    def is_available(self) -> bool: ...


class OSKeystore(Keystore):
    """Stores tokens in the OS credential store via the keyring library."""

    def __init__(self) -> None:
        self.unavailable_reason = ""

    @property
    def uses_external_storage(self) -> bool:
        return True

    def store_token(self, instance_url: str, token: str) -> None:
        with _keyring_lock():
            acl_error: Optional[Exception] = None
            if sys.platform == "darwin" and _writes_to_the_apple_keychain():
                try:
                    _macos_store_token(instance_url, token)
                    return
                except Exception as exc:
                    acl_error = exc
            try:
                keyring.set_password(KEYRING_SERVICE, instance_url, token)
            except Exception as exc:
                raise KeystoreError(KeystoreFailure.DENIED, str(exc)) from exc
            if acl_error is not None:
                ui.display_warning(
                    "Could not grant every ggshield binary access to the token "
                    f"in the Keychain ({acl_error}). The token was stored, but "
                    "macOS may ask for permission again, and the AI hook cannot "
                    "answer that dialog."
                )

    def read_token(self, instance_url: str) -> str:
        try:
            with _keyring_lock():
                token = keyring.get_password(KEYRING_SERVICE, instance_url)
        except Exception as exc:
            raise KeystoreError(KeystoreFailure.DENIED, str(exc)) from exc
        if token is None:
            raise KeystoreError(KeystoreFailure.NOT_FOUND)
        return token

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
                self.unavailable_reason = "no credential store backend is available"
                return False
            # Hold the lock across the probe so it doesn't race the token
            # reads of concurrent processes.
            with _keyring_lock():
                keyring.get_password(KEYRING_SERVICE, "__ggshield_probe__")
            return True
        except Exception as exc:
            self.unavailable_reason = str(exc) or type(exc).__name__
            return False


class FileKeystore(Keystore):
    """Fallback: tokens remain in the YAML config file."""

    def __init__(
        self,
        failure: KeystoreFailure = KeystoreFailure.DISABLED,
        detail: str = "",
    ):
        self.failure = failure
        self.detail = detail

    @property
    def uses_external_storage(self) -> bool:
        return False

    def store_token(self, instance_url: str, token: str) -> None:
        pass

    def read_token(self, instance_url: str) -> str:
        raise KeystoreError(self.failure, self.detail)

    def delete_token(self, instance_url: str) -> None:
        pass

    def is_available(self) -> bool:
        return True


_keystore: Optional[Keystore] = None


def get_keystore() -> Keystore:
    """Return the active token store, selecting keyring when available."""
    global _keystore
    if _keystore is not None:
        return _keystore

    if getenv_bool("GGSHIELD_NO_KEYRING", default=False):
        logger.debug("Keyring disabled via GGSHIELD_NO_KEYRING env var")
        _keystore = FileKeystore(KeystoreFailure.DISABLED)
        return _keystore

    store = OSKeystore()
    if store.is_available():
        _keystore = store
    else:
        logger.debug(
            "Keyring is not available (%s), falling back to file-based token storage",
            store.unavailable_reason,
        )
        _keystore = FileKeystore(KeystoreFailure.UNAVAILABLE, store.unavailable_reason)
    return _keystore


def reset_keystore() -> None:
    """Reset the cached token store. Used in tests."""
    global _keystore
    _keystore = None
