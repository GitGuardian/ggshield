"""Machine-wide service-account auth for fleet/MDM deployments.

A root-provisioned ``(instance, token)`` pair that every account on the machine
falls back to — below ``GITGUARDIAN_API_KEY`` and a user's own ``auth login``, so a
developer's personal token always wins. Written by ``ggshield machine setup`` when
given a service-account token; read here during config resolution.

The file is world-readable by design: a single service-account identity shared by
every account on the machine (the same trade-off as the system-wide git hooks).
"""

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from ggshield.core.dirs import get_system_config_dir


logger = logging.getLogger(__name__)

_AUTH_FILENAME = "auth.yaml"


@dataclass
class SystemAuth:
    instance: str
    token: str


def get_system_auth_path() -> Path:
    return get_system_config_dir() / _AUTH_FILENAME


def read_system_auth() -> Optional[SystemAuth]:
    """Return the machine-wide service-account auth, or None if absent/unreadable.

    Never raises — a missing or malformed file simply means "no machine-wide auth".
    """
    path = get_system_auth_path()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        logger.warning("Ignoring malformed system auth file %s: %s", path, exc)
        return None
    instance = data.get("instance") if isinstance(data, dict) else None
    token = data.get("token") if isinstance(data, dict) else None
    if not instance or not token:
        return None
    return SystemAuth(instance=instance, token=token)


def write_system_auth(instance: str, token: str) -> Path:
    """Write the machine-wide service-account auth and return its path.

    The file and its directory are made world-readable (0644 / 0755) so every
    account on the machine can use the token. Requires write access to the system
    config dir (i.e. root); the OSError propagates otherwise.
    """
    path = get_system_auth_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o755)
    except OSError:
        pass
    path.write_text(
        yaml.safe_dump({"instance": instance, "token": token}, default_flow_style=False),
        encoding="utf-8",
    )
    os.chmod(path, 0o644)
    return path
