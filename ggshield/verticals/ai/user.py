"""
This module provides information about the current user.

It should be eventually merged with the logic used by local scanning.
"""

import subprocess
from typing import Optional

from pygitguardian.models import UserInfo

from ggshield.core.machine_id import _get_hostname, _get_machine_id, _get_username


def get_user_info(machine_id: Optional[str] = None) -> UserInfo:
    """Collect hostname, username, machine identifier, and best-effort email."""
    return UserInfo(
        hostname=_get_hostname(),
        username=_get_username(),
        machine_id=machine_id or _get_machine_id(),
        user_email=_get_user_email(),
    )


def _get_user_email() -> Optional[str]:
    """Best-effort user email; tries `git config user.email` first."""
    try:
        result = subprocess.run(
            ["git", "config", "user.email"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            email = (result.stdout or "").strip()
            return email or None
    except (OSError, subprocess.SubprocessError):
        pass
    return None
