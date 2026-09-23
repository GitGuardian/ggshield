"""
Generic, hardened text file I/O shared by the honeytoken placement backends
(``aws_profile``, ``kubeconfig_file``) and the ownership fix-up in ``targets``.

Content-agnostic (plain text in/out): the backends own parsing and decisions, this
module owns the one implementation of the root-fan-out hardening.

On POSIX every op is anchored to a directory fd opened ``O_NOFOLLOW|O_DIRECTORY``: the fd
pins the real inode, so a symlink swapped in after a check (TOCTOU) has no effect, and an
exclusive advisory lock serialises concurrent writers for the read-modify-write window.
Platforms without dir fds (Windows) fall back to a path-based check.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import Optional


# No-follow, fd-anchored file ops available (POSIX). os.rename (not os.replace) carries
# dir_fd on Linux+macOS and replaces atomically on POSIX.
FD_HARDENED = (
    hasattr(os, "O_NOFOLLOW")
    and os.open in os.supports_dir_fd
    and os.rename in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
)


# A real credentials/kubeconfig file is a few KiB. The cap stops an unprivileged user
# from making the root fan-out allocate a multi-GiB "config" they planted in their home.
MAX_FILE_SIZE = 8 * 1024 * 1024


class SecureFileError(Exception):
    """A file could not be read/written safely (symlink swap, non-dir, fs failure)."""


def _check_size(size: int, where: object) -> None:
    if size > MAX_FILE_SIZE:
        raise SecureFileError(
            f"refusing to edit {where}: file is {size} bytes, larger than the "
            f"{MAX_FILE_SIZE} byte limit for a credentials file"
        )


def require_safe_backend() -> None:
    """Fail closed on POSIX without dir fds: the only alternative is TOCTOU-prone path
    ops, and POSIX is where the root fan-out makes that exploitable. Windows is exempt.
    """
    if os.name == "posix" and not FD_HARDENED:
        raise SecureFileError(
            "this platform lacks the directory file-descriptor support "
            "(O_NOFOLLOW/dir_fd) required to place honeytokens safely — refusing"
        )


# --- no-follow, fd-anchored backend (POSIX) ---------------------------------------


def open_dir_fd(directory: Path, *, create: bool) -> int:
    """Open ``directory`` ``O_NOFOLLOW|O_DIRECTORY``, returning an fd that pins the real
    inode (swap-immune) and holds an exclusive advisory lock for the read-modify-write
    window. Symlink/non-dir → ``SecureFileError``. ``create`` makes a missing dir 0700;
    else ``FileNotFoundError`` propagates (callers treat absent as a no-op)."""
    import fcntl

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        fd = os.open(directory, flags)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except FileNotFoundError:
        if not create:
            raise
    except OSError as exc:
        raise SecureFileError(
            f"refusing to use {directory}: not a real directory (symlink?): {exc}"
        )
    # Create the home chain, then the leaf dir itself 0700 (the no-follow re-open is the gate).
    os.makedirs(directory.parent, mode=0o700, exist_ok=True)
    try:
        os.mkdir(directory, 0o700)
    except FileExistsError:
        pass
    try:
        fd = os.open(directory, flags)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except OSError as exc:
        raise SecureFileError(
            f"refusing to use {directory}: not a real directory (symlink?): {exc}"
        )


def read_via_fd(dir_fd: int, name: str) -> Optional[str]:
    """Read ``name`` under the pinned dir, no-follow. ``None`` if absent."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:  # ELOOP → the file itself is a symlink
        raise SecureFileError(f"refusing to read through symlinked file {name}: {exc}")
    try:
        _check_size(os.fstat(fd).st_size, name)
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        return _read_text(handle, name)


def _read_text(handle, where) -> str:  # type: ignore[no-untyped-def]
    # A binary or non-UTF-8 file is "not something we can safely edit", not a codec
    # traceback for the operator.
    try:
        return handle.read()
    except UnicodeDecodeError:
        raise SecureFileError(f"refusing to edit {where}: not a UTF-8 text file")


def atomic_write_via_fd(dir_fd: int, name: str, content: str) -> None:
    """Atomically (re)write ``name`` under the pinned dir, preserving its mode (new file
    → 0600), via an ``O_EXCL`` temp + no-follow ``os.rename`` anchored on both ends."""
    try:
        mode = stat.S_IMODE(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)
    except FileNotFoundError:
        mode = 0o600
    fd = -1
    tmp = None
    for _ in range(8):
        candidate = f".plant.{os.urandom(8).hex()}.tmp"
        try:
            fd = os.open(
                candidate,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                0o600,
                dir_fd=dir_fd,
            )
            tmp = candidate
            break
        except FileExistsError:
            continue
    if tmp is None:
        raise SecureFileError(f"could not create a temp file in {name}'s directory")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            # Commit the data before the rename publishes it: a crash in between would
            # otherwise leave a zero-length file where the user's real config was.
            handle.flush()
            os.fsync(handle.fileno())
        os.rename(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dir_fd)
        except OSError:
            pass
        raise
    _fsync_quietly(dir_fd)
    ffd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    try:
        os.fchmod(ffd, mode)
    finally:
        os.close(ffd)


def _fsync_quietly(fd: int) -> None:
    """Persist a directory entry (the rename) — best effort, some filesystems refuse
    fsync on directories and the data itself is already durable."""
    try:
        os.fsync(fd)
    except OSError:
        pass


def unlink_via_fd(dir_fd: int, name: str) -> None:
    """Best-effort unlink of ``name`` under the pinned dir."""
    try:
        os.unlink(name, dir_fd=dir_fd)
    except OSError:
        pass


# --- path-based fallback (no dir fds / O_NOFOLLOW, e.g. Windows) -------------------


def reject_symlinked_target(path: Path) -> None:
    """Best-effort pre-check for the path-based (non-POSIX) backend."""
    if path.parent.is_symlink():
        raise SecureFileError(f"refusing to use {path.parent}: parent is a symlink")
    if path.is_symlink():
        raise SecureFileError(f"refusing to write through symlinked file {path}")


def read_path(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    _check_size(path.stat().st_size, path)
    with open(path, "r", encoding="utf-8") as handle:
        return _read_text(handle, path)


def atomic_write_path(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        mode = 0o600
    fd, tmp = tempfile.mkstemp(prefix=".plant.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        # Swap first (temp keeps mkstemp's 0600 while holding the secret), then chmod.
        os.replace(tmp, path)
        os.chmod(path, mode)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def unlink_path(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass
