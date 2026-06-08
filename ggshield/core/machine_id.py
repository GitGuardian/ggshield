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
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Optional

from ggshield.core.dirs import get_user_home_dir


_MAC_IOREG_UUID_RE = re.compile(r'"IOPlatformUUID"\s*=\s*"([^"]+)"')


def _get_hostname() -> str:
    if sys.platform == "win32":
        name = (os.environ.get("COMPUTERNAME") or "").strip()
        if name:
            return name
    try:
        return socket.gethostname() or "unknown"
    except OSError:
        return "unknown"


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
        )
        if result.returncode != 0 or not result.stdout:
            return None
        match = _MAC_IOREG_UUID_RE.search(result.stdout)
        if match:
            return match.group(1).strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _parse_wmic_uuid(stdout: str) -> Optional[str]:
    for line in stdout.splitlines():
        line = line.strip()
        if not line or line.upper() == "UUID":
            continue
        try:
            return str(uuid.UUID(line))
        except ValueError:
            pass
    return None


def _get_windows_system_id() -> Optional[str]:
    try:
        result = subprocess.run(
            ["wmic", "csproduct", "get", "uuid"],
            capture_output=True,
            text=True,
            check=False,
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
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystemProduct).UUID",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0 and result.stdout:
            try:
                return str(uuid.UUID(result.stdout.strip()))
            except ValueError:
                pass
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _get_machine_id() -> str:

    # In case Satori generated a machine id, use it.
    path = get_user_home_dir() / ".satori" / "machine_id"
    try:
        if path.is_file():
            cached = _read_first_nonempty_line(path)
            if cached:
                return cached
    except OSError:
        pass

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

    # If everything failed, use a random UUID.
    # Store it so that satori can use it.
    new_id = str(uuid.uuid4())
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(new_id + "\n")
    except OSError:
        pass

    return new_id
