import os
import sys
from pathlib import Path

from platformdirs import (
    site_config_dir,
    site_data_dir,
    user_cache_dir,
    user_config_dir,
    user_data_dir,
)

from ggshield.utils.git_shell import NotAGitDirectory, get_git_root


APPNAME = "ggshield"
APPAUTHOR = "GitGuardian"


def get_user_home_dir() -> Path:
    try:
        # See tests/conftest.py for details
        return Path(os.environ["GG_USER_HOME_DIR"])
    except KeyError:
        return Path.home()


def get_editor_user_data_dir(app_name: str) -> Path:
    """Return the per-OS ``User`` data directory of a VSCode-family editor.

    VSCode and its forks (Cursor, …) keep their per-user state under an
    OS-specific base — ``~/.config`` on Linux, ``~/Library/Application Support``
    on macOS, ``~/AppData/Roaming`` on Windows — so a hardcoded ``~/.config``
    path finds nothing off Linux. app_name is the editor's directory name
    ("Code", "Cursor").
    """
    home = get_user_home_dir()
    if sys.platform == "darwin":
        base = home / "Library" / "Application Support"
    elif sys.platform == "win32":
        base = home / "AppData" / "Roaming"
    else:
        base = home / ".config"
    return base / app_name / "User"


def get_config_dir() -> Path:
    try:
        # See tests/conftest.py for details
        return Path(os.environ["GG_CONFIG_DIR"])
    except KeyError:
        return Path(user_config_dir(appname=APPNAME, appauthor=APPAUTHOR))


def get_cache_dir() -> Path:
    try:
        # See tests/conftest.py for details
        return Path(os.environ["GG_CACHE_DIR"])
    except KeyError:
        return Path(user_cache_dir(appname=APPNAME, appauthor=APPAUTHOR))


def get_data_dir() -> Path:
    try:
        # See tests/conftest.py for details
        return Path(os.environ["GG_DATA_DIR"])
    except KeyError:
        return Path(
            user_data_dir(appname=APPNAME, appauthor=APPAUTHOR)
        )  # pragma: no cover


def get_system_data_dir() -> Path:
    """Machine-wide (all users) data dir, e.g. for system-scoped git hooks.

    The system counterpart to :func:`get_data_dir`; used when ``machine setup`` runs
    as root and installs git hooks for every user on the machine.
    """
    try:
        # See tests/conftest.py for details
        return Path(os.environ["GG_SYSTEM_DATA_DIR"])
    except KeyError:
        return Path(site_data_dir(appname=APPNAME, appauthor=APPAUTHOR))


def get_system_config_dir() -> Path:
    """Machine-wide (all users) config dir, the system counterpart to
    :func:`get_config_dir`. Holds the system enterprise config that lets an
    admin enable a plugin for every user from one root-owned file.
    """
    try:
        # See tests/conftest.py for details
        return Path(os.environ["GG_SYSTEM_CONFIG_DIR"])
    except KeyError:
        return Path(site_config_dir(appname=APPNAME, appauthor=APPAUTHOR))


def is_root() -> bool:
    """True when running as root on POSIX; always False on Windows."""
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def make_world_readable(path: Path) -> None:
    """Best-effort: make ``path`` readable by every user — directories
    world-traversable (0o755), files world-readable (0o644).

    Used after a root (machine-wide) install writes into a shared system
    location: root's umask can leave the new file/dir owner-only, so other
    users could not read or traverse what root just wrote. These paths hold
    only plugin code, metadata, and enablement — nothing secret. No-op on
    failure (e.g. a path owned by another user)."""
    try:
        path.chmod(0o755 if path.is_dir() else 0o644)
    except OSError:
        pass


def make_tree_world_readable(root: Path) -> None:
    """Apply :func:`make_world_readable` to ``root`` and everything under it."""
    make_world_readable(root)
    if not root.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(root):
        for name in (*dirnames, *filenames):
            make_world_readable(Path(dirpath) / name)


def create_world_traversable_dir(path: Path) -> None:
    """``mkdir -p`` ``path`` and make every directory created here — plus
    ``path`` itself — world-traversable (0o755).

    A root install under a restrictive umask must stay reachable by every
    user. ``mkdir(parents=True)`` would create new intermediate directories
    (e.g. those of a nested ``GG_SYSTEM_*_DIR``) owner-only, so widen the
    whole chain this call creates. Pre-existing ancestors keep their mode;
    ``path`` is always widened in case an earlier ggshield created it before
    this behaviour existed."""
    missing = []
    p = path
    while not p.exists():
        missing.append(p)
        if p.parent == p:  # filesystem root
            break
        p = p.parent
    path.mkdir(parents=True, exist_ok=True)
    for created in missing:
        make_world_readable(created)
    make_world_readable(path)


def get_plugins_dir(*, create: bool = False) -> Path:
    """Return the per-user plugin directory inside the ggshield data directory."""
    return _ensure(get_data_dir() / "plugins", create)


def get_system_plugins_dir(*, create: bool = False) -> Path:
    """Machine-wide plugin directory; where a root install lands so every user
    can load it (made world-traversable for that reason)."""
    system_data = get_system_data_dir()
    path = system_data / "plugins"
    if create:
        # Widen the whole chain root just created (including any intermediate
        # ancestors of a nested system dir), not only the leaf, so non-root
        # users can traverse down to the plugins regardless of root's umask.
        create_world_traversable_dir(path)
        make_world_readable(system_data)
    return path


def _ensure(path: Path, create: bool) -> Path:
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path


def get_project_root_dir(path: Path) -> Path:
    """
    Returns the source basedir required to find file within filesystem.
    """
    try:
        return get_git_root(wd=path).resolve()
    except NotAGitDirectory:
        # In case we are not in a Git repository
        return path.resolve()
