"""
Machine and current-user identity, shared across verticals.

The machine identifier is derived from a stable per-machine system id, so a machine
reports a consistent ``machine_id`` regardless of which feature (AI discovery,
honeytoken planting…) produces it — this keeps the GitGuardian ``EndpointUser`` join
key consistent.
"""

import getpass
import os
import platform
import re
import socket
import stat
import subprocess
import sys
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Optional

from ggshield.core.dirs import get_user_home_dir


_MAC_IOREG_UUID_RE = re.compile(r'"IOPlatformUUID"\s*=\s*"([^"]+)"')

# Bound the system-id subprocesses: a hung WMI service must not freeze scan
# startup (and thus git hooks) indefinitely — on timeout we fall through to the
# cache/random path.
_SUBPROCESS_TIMEOUT = 5


def _get_hostname() -> str:
    if sys.platform == "win32":
        name = (os.environ.get("COMPUTERNAME") or "").strip()
        if name:
            return name
    try:
        return socket.gethostname() or "unknown"
    except OSError:
        return "unknown"


@lru_cache(maxsize=1)
def _get_username() -> str:
    try:
        return getpass.getuser()
    except Exception:
        pass
    try:
        return os.getlogin()
    except Exception:
        return "unknown"


def _read_first_nonempty_line(path: Path) -> Optional[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    for line in text:
        stripped = line.strip()
        if stripped:
            return stripped
    return None


def _get_linux_system_id() -> Optional[str]:
    for candidate in (
        Path("/etc/machine-id"),
        Path("/sys/class/dmi/id/product_uuid"),
        Path("/var/lib/dbus/machine-id"),
    ):
        value = _read_first_nonempty_line(candidate)
        if value:
            return value
    return None


def _get_macos_system_id() -> Optional[str]:
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True,
            text=True,
            check=False,
            timeout=_SUBPROCESS_TIMEOUT,
        )
        if result.returncode != 0 or not result.stdout:
            return None
        match = _MAC_IOREG_UUID_RE.search(result.stdout)
        if match:
            return match.group(1).strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


# The character class is ASCII-only on purpose (no \d / \w, which also match
# fullwidth Unicode digits).
_UUID_HEX_RE = re.compile(r"[0-9a-fA-F]{32}")

# Placeholder SMBIOS UUIDs reported by unconfigured or cloned firmware (blank
# boards, golden images, vendor defaults). They identify an image, not a
# machine: adopting one collapses every such endpoint in an account onto one
# machine_id. Aligned with osquery's kPlaceholderHardwareUUIDList.
_SENTINEL_UUID_HEX = frozenset(
    (
        "0" * 32,
        "f" * 32,
        "03000200040005000006000700080009",  # AMI default
        "030201000504070608090a0b0c0d0e0f",  # byte-order test pattern
        "10000000000080000040000000000000",
        "fe" * 16,  # Windows placeholder (Win 11 IoT LTSC)
    )
)


def _normalize_uuid(value: str) -> Optional[str]:
    """Canonicalize a UUID string to lowercase dashed form.

    Mirrors satori's ``normalize_uuid`` — deliberately stricter than
    ``uuid.UUID``, whose lax ``int(x, 16)`` parsing accepts ``0x``/``+``/``_``
    and fullwidth digits. The machine-identity contract requires exactly 32 hex
    digits so both tools derive the same id, or both fall back, on the same
    input. Sentinel (placeholder) UUIDs are rejected too.
    """
    stripped = value.strip().replace("urn:", "").replace("uuid:", "")
    hex_ = stripped.strip("{}").replace("-", "")
    if not _UUID_HEX_RE.fullmatch(hex_):
        return None
    hex_ = hex_.lower()
    if hex_ in _SENTINEL_UUID_HEX:
        return None
    return f"{hex_[:8]}-{hex_[8:12]}-{hex_[12:16]}-{hex_[16:20]}-{hex_[20:]}"


def _parse_wmic_uuid(stdout: str) -> Optional[str]:
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.upper() == "UUID":
            continue
        normalized = _normalize_uuid(line)
        if normalized:
            return normalized
    return None


def _windows_binary(*relative_parts: str) -> str:
    """Absolute path to a Windows system binary, resolved from ``%SystemRoot%``.

    Invoking ``wmic``/``powershell`` by bare name lets a binary planted in the
    current working directory (which ``CreateProcess`` searches before
    ``System32``) run instead — a local code-execution vector. Pin the absolute
    path so only the genuine system binary can run.
    """
    system_root = os.environ.get("SystemRoot") or r"C:\Windows"
    return os.path.join(system_root, *relative_parts)


def _get_windows_system_id() -> Optional[str]:
    try:
        result = subprocess.run(
            [
                _windows_binary("System32", "wbem", "WMIC.exe"),
                "csproduct",
                "get",
                "uuid",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=_SUBPROCESS_TIMEOUT,
        )
        if result.returncode == 0 and result.stdout:
            parsed = _parse_wmic_uuid(result.stdout)
            if parsed:
                return parsed
    except (OSError, subprocess.SubprocessError):
        pass

    try:
        result = subprocess.run(
            [
                _windows_binary(
                    "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
                ),
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystemProduct).UUID",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=_SUBPROCESS_TIMEOUT,
        )
        if result.returncode == 0 and result.stdout:
            normalized = _normalize_uuid(result.stdout.strip())
            if normalized:
                return normalized
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _machine_id_cache_path() -> Path:
    """Shared random-UUID cache, read and written by both ggshield and satori.

    Kept in sync with satori's ``satori_dir()`` (``~/.ggshield``) so that a
    machine with no derivable hardware id still converges on a single
    ``machine_id`` across both tools. See the machine-identity contract doc.
    """
    return get_user_home_dir() / ".ggshield" / "machine_id"


# A legitimate cache holds one 36-byte UUID line; cap reads so a corrupt or
# planted multi-GB file can't balloon memory. Mirrors satori's cap.
_CACHE_READ_MAX = 65536


def _is_trusted_cache_owner(file_uid: int, euid: int, home_uid: Optional[int]) -> bool:
    """Whether ``file_uid`` may own the fallback-id cache.

    Identity is client-asserted end to end (the server stores whatever
    machine_id a client reports), so an own-files-only rule buys no integrity.
    The requirement is that no OTHER unprivileged user can plant the file:
    trust the current user, root, and the owner of the home the cache lives
    in — so a ``sudo -E`` run and a plain user run converge on one id instead
    of diverging.
    """
    return file_uid == euid or file_uid == 0 or file_uid == home_uid


def _read_trusted_cache_line(path: Path) -> Optional[str]:
    """First non-empty line of the shared fallback-id cache, if trustworthy.

    On POSIX, refuse a group/world-writable file or one owned by an unrelated
    user (see ``_is_trusted_cache_owner``), so a local attacker can't pre-seed
    the machine id for another account's run (mirrors satori's
    ``paths::open_trusted_cache_file``). Opens with ``O_NOFOLLOW`` and
    validates ownership/mode on the very descriptor it reads: a stat-then-open
    by path could be raced, follows planted symlinks, and blocks forever on a
    FIFO.
    """
    flags = os.O_RDONLY
    if os.name == "posix":
        flags |= os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        if os.name == "posix":
            if st.st_mode & 0o022:
                return None
            try:
                home_uid: Optional[int] = os.stat(path.parent.parent).st_uid
            except OSError:
                home_uid = None
            if not _is_trusted_cache_owner(st.st_uid, os.geteuid(), home_uid):
                return None
        data = os.read(fd, _CACHE_READ_MAX)
    except OSError:
        return None
    finally:
        os.close(fd)
    for line in data.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return None


def _write_machine_id_cache(path: Path, value: str) -> None:
    """Persist the fallback id as an owner-writable (0644) regular file.

    World-readable so a run under another trusted identity (root service,
    ``sudo -E``) can adopt the id — the value is no more secret locally than
    the world-readable ``/etc/machine-id``. Never group/world-WRITABLE: a
    umask-derived write can be (umask 002 is the RHEL/Fedora default), which
    the trust gate itself would reject on the next run — the id would then
    churn forever, one new server-side Endpoint row per run. Never write
    through an existing path either: a foreign-owned file is left untouched
    (root under ``sudo -E`` must not clobber the user's id), anything else
    (loose-permission file, planted symlink) is replaced, since in-place
    truncation preserves the untrusted mode.
    """
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            st = os.lstat(path)
        except OSError:
            st = None
        if st is not None:
            if os.name == "posix" and st.st_uid != os.geteuid():
                return
            os.unlink(path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if os.name == "posix":
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o644)
        try:
            if os.name == "posix":
                os.fchmod(fd, 0o644)
            os.write(fd, (value + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except OSError:
        pass


@lru_cache(maxsize=1)
def _get_machine_id() -> str:
    system = platform.system().lower()
    system_id = None

    if system == "darwin":
        system_id = _get_macos_system_id()
    elif system == "linux":
        system_id = _get_linux_system_id()
    elif sys.platform == "win32":
        system_id = _get_windows_system_id()

    if system_id:
        return system_id

    # No hardware id: reuse the shared random-UUID cache if present and trusted,
    # otherwise mint one and persist it so ggshield and satori agree on the
    # fallback id.
    path = _machine_id_cache_path()
    cached = _read_trusted_cache_line(path)
    if cached:
        return cached

    new_id = str(uuid.uuid4())
    _write_machine_id_cache(path, new_id)
    return new_id
