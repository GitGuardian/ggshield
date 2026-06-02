"""
Resolve which OS users to plant honeytokens for, and apply on-disk ownership/perms.

Resolution rules:
- ``--user-dir`` → single target at that home (no uid, testing/edge).
- ``--user`` → that user, resolved via the passwd database.
- root, no flags → fan out to every plausible user home (privileged accounts included).
- non-root, no flags → the current user only.

Machine identity reuses ``ggshield.core.machine_id`` so the plant reports the **same**
``(machine_id, username, hostname)`` as the rest of ggshield (the GIM ``EndpointUser``
join key).
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from ggshield.core.dirs import get_user_home_dir
from ggshield.core.machine_id import _get_hostname, _get_machine_id, _get_username


# Home roots that look like real human-user spaces (kept even if the shell is nologin,
# e.g. gitlab-runner).
_USER_HOME_ROOTS = (
    "/home",
    "/Users",
    "/usr/home",
    "/var/home",
    "/export/home",
    "/u",
    "/srv/home",
)


@dataclass
class Target:
    """A resolved planting target: which OS user and where their home is."""

    username: str
    home: Path
    # Numeric uid for chown when running as root (None when not needed/known).
    uid: Optional[int]


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def machine_info_for(username: str) -> Dict[str, str]:
    """The ``machine_info`` triple for a target: shared machine_id + hostname, the
    target's username (so a root fan-out reports each user correctly)."""
    return {
        "machine_id": _get_machine_id(),
        "username": username,
        "hostname": _get_hostname(),
    }


def resolve_targets(user: Optional[str], user_dir: Optional[Path]) -> List[Target]:
    """Resolve the set of users to plant for. Raises ``LookupError`` if an explicit
    ``--user`` can't be resolved."""
    if user_dir is not None:
        return [Target(username=user or _get_username(), home=user_dir, uid=None)]

    if user is not None:
        home, uid, _gid = _passwd_for_name(user)
        return [Target(username=user, home=home, uid=uid)]

    if is_root():
        return _enumerate_user_homes()

    return [Target(username=_get_username(), home=get_user_home_dir(), uid=None)]


def apply_perms_and_owner(path: Path, target: Target, running_as_root: bool) -> None:
    """Tighten perms (file 0600, dir 0700) and, as root, chown the file + its ``.aws``
    dir to the target user so they own their decoy. No-op off Unix."""
    if os.name != "posix":
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    parent = path.parent
    try:
        os.chmod(parent, 0o700)
    except OSError:
        pass

    if running_as_root and target.uid is not None:
        gid = _gid_for_uid(target.uid)
        gid = gid if gid is not None else target.uid
        try:
            os.chown(path, target.uid, gid)
            os.chown(parent, target.uid, gid)
        except OSError:
            pass


def _passwd_for_name(name: str):
    import pwd

    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        raise LookupError(f"could not resolve home directory for user '{name}'")
    return Path(entry.pw_dir), entry.pw_uid, entry.pw_gid


def _gid_for_uid(uid: int) -> Optional[int]:
    import pwd

    try:
        return pwd.getpwuid(uid).pw_gid
    except KeyError:
        return None


def _is_interactive_shell(shell: str) -> bool:
    return bool(shell) and not (
        shell.endswith("/nologin") or shell.endswith("/false") or shell == "/bin/sync"
    )


def _looks_like_common_user_home(home: str) -> bool:
    return any(home == root or home.startswith(root + "/") for root in _USER_HOME_ROOTS)


def _enumerate_user_homes() -> List[Target]:
    """Enumerate plausible user homes via the passwd database (Unix). Keeps root, homes
    under common human-user roots, and interactive accounts (uid >= 500); dedups by real
    path (conservative filter)."""
    if (
        sys.platform == "win32"
    ):  # pragma: no cover - unreachable (is_root() is False on Windows)
        return [Target(username=_get_username(), home=get_user_home_dir(), uid=None)]

    import pwd

    targets: List[Target] = []
    seen = set()
    for entry in pwd.getpwall():
        home = entry.pw_dir or ""
        uid = entry.pw_uid
        shell = entry.pw_shell or ""
        if not home or not os.path.isdir(home):
            continue
        if not os.access(home, os.R_OK):
            continue
        keep = (
            uid == 0
            or _looks_like_common_user_home(home)
            or (uid >= 500 and _is_interactive_shell(shell))
        )
        if not keep:
            continue
        key = os.path.realpath(home)
        if key in seen:
            continue
        seen.add(key)
        targets.append(Target(username=entry.pw_name, home=Path(home), uid=uid))

    targets.sort(key=lambda t: (t.username, str(t.home)))
    return targets
