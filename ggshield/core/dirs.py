import logging
import os
import stat
import sys
from pathlib import Path
from typing import Callable, List, Optional, Set, Tuple

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

logger = logging.getLogger(__name__)

# Keep root installs visible across sessions with different XDG settings.
_LINUX_SYSTEM_DATA_DIR = Path("/usr/local/share") / APPNAME
_LINUX_SYSTEM_CONFIG_DIR = Path("/etc/xdg") / APPNAME
# platformdirs honors XDG vars (and Homebrew prefixes) on macOS: pin the path.
_MACOS_SYSTEM_DIR = Path("/Library/Application Support") / APPNAME


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
    """Fixed write location for machine-wide plugins and Git hooks."""
    try:
        # See tests/conftest.py for details
        return Path(os.environ["GG_SYSTEM_DATA_DIR"])
    except KeyError:
        pass
    if sys.platform == "darwin":
        return _MACOS_SYSTEM_DIR
    if sys.platform == "win32":
        return Path(site_data_dir(appname=APPNAME, appauthor=APPAUTHOR))
    return _LINUX_SYSTEM_DATA_DIR


def get_system_config_dir() -> Path:
    """Fixed write location for machine-wide enterprise config."""
    try:
        # See tests/conftest.py for details
        return Path(os.environ["GG_SYSTEM_CONFIG_DIR"])
    except KeyError:
        pass
    if sys.platform == "darwin":
        return _MACOS_SYSTEM_DIR
    if sys.platform == "win32":
        return Path(site_config_dir(appname=APPNAME, appauthor=APPAUTHOR))
    return _LINUX_SYSTEM_CONFIG_DIR


def _is_safe_system_dir(path: Path) -> bool:
    """Check that the directory and its ancestors are controlled by root or us."""
    try:
        # Check the route to the resolved directory too. An unsafe ancestor
        # could replace a symlink even when its current target is safe.
        pending = [path, path.resolve(strict=True)]
        checked = set()
        euid = os.geteuid()
        while pending:
            directory = pending.pop()
            for candidate in reversed((directory, *directory.parents)):
                if candidate in checked:
                    continue
                checked.add(candidate)
                st = candidate.lstat()
                if st.st_uid not in (0, euid):
                    return False
                if stat.S_ISLNK(st.st_mode):
                    pending.append(candidate.parent / candidate.readlink())
                elif not stat.S_ISDIR(st.st_mode) or st.st_mode & 0o022:
                    return False
    except (OSError, RuntimeError):
        return False
    return True


def is_safe_system_path(
    path: Path, *, directory: bool = False, allow_missing: bool = False
) -> bool:
    """Check an entry in a secondary system directory without following symlinks."""
    try:
        st = path.lstat()
    except FileNotFoundError:
        return allow_missing
    except (OSError, ValueError) as e:
        logger.debug("Cannot inspect system path %s: %s", path, e)
        return False

    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        expected_type(st.st_mode)
        and st.st_uid in (0, os.geteuid())
        and not (st.st_mode & 0o022)
    ):
        return True
    logger.debug("Ignoring unsafe system path %s", path)
    return False


_UNSAFE_REASON = "ignored: not owned by root, or writable by others"

# (path, reason) pairs for XDG entries left out of a read list.
IgnoredDirs = List[Tuple[Path, str]]


def _get_system_dirs(
    override_var: str,
    fixed: Path,
    xdg_var: str,
    platformdirs_func: Callable[..., str],
    ignored: Optional[IgnoredDirs] = None,
) -> List[Path]:
    """Read list for a machine-wide dir, highest precedence first: the fixed
    write dir, then every XDG entry that passes :func:`_is_safe_system_dir`.
    Entries left out are appended to ``ignored`` (for ``plugin list -v``)."""
    if override_var in os.environ or sys.platform == "win32":
        return [fixed]
    # macOS ACLs can grant write access that mode bits do not show.
    if sys.platform == "darwin" and is_root():
        return [fixed]

    dirs = [fixed]
    # platformdirs versions differ in whether they honor XDG on macOS.
    multipath = os.environ.get(xdg_var, "").strip() or platformdirs_func(multipath=True)
    for entry in multipath.split(os.pathsep):
        entry = entry.strip()
        if not entry:
            continue
        path = Path(entry) / APPNAME
        if not path.is_absolute() or path in dirs:
            continue
        if not _is_safe_system_dir(path):
            logger.debug("Ignoring unsafe or missing system dir %s", path)
            if ignored is not None:
                ignored.append((path, _ignored_reason(path)))
            continue
        dirs.append(path)
    return dirs


def _ignored_reason(path: Path) -> str:
    try:
        path.stat()
    except FileNotFoundError:
        return "not found"
    except OSError as e:
        return f"cannot access: {e}"
    return _UNSAFE_REASON


def get_system_data_dirs(ignored: Optional[IgnoredDirs] = None) -> List[Path]:
    """Machine-wide data dirs to read, highest precedence first: the fixed write
    dir, then the other ``XDG_DATA_DIRS`` entries (safe ones only), deduplicated."""
    return _get_system_dirs(
        "GG_SYSTEM_DATA_DIR",
        get_system_data_dir(),
        "XDG_DATA_DIRS",
        site_data_dir,
        ignored,
    )


def get_system_config_dirs(ignored: Optional[IgnoredDirs] = None) -> List[Path]:
    """Machine-wide config dirs to read, highest precedence first (see
    :func:`get_system_data_dirs`)."""
    return _get_system_dirs(
        "GG_SYSTEM_CONFIG_DIR",
        get_system_config_dir(),
        "XDG_CONFIG_DIRS",
        site_config_dir,
        ignored,
    )


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


def get_system_plugins_dirs(ignored: Optional[IgnoredDirs] = None) -> List[Path]:
    """Machine-wide plugin dirs to read, highest precedence first. XDG entries
    left out are appended to ``ignored`` (as their ``plugins`` dir)."""
    ignored_data: IgnoredDirs = []
    dirs = get_system_data_dirs(ignored_data)
    if ignored is not None:
        ignored.extend((path / "plugins", reason) for path, reason in ignored_data)
    plugins_dirs = [dirs[0] / "plugins"]
    for data_dir in dirs[1:]:
        plugins_dir = data_dir / "plugins"
        try:
            plugins_dir.lstat()
        except FileNotFoundError:
            plugins_dirs.append(plugins_dir)
            continue
        except OSError as e:
            logger.debug("Cannot inspect plugins dir %s: %s", plugins_dir, e)
            if ignored is not None:
                ignored.append((plugins_dir, f"cannot access: {e}"))
            continue
        if not _is_safe_system_dir(plugins_dir):
            logger.debug("Ignoring unsafe plugins dir %s", plugins_dir)
            if ignored is not None:
                ignored.append((plugins_dir, _UNSAFE_REASON))
            continue
        plugins_dirs.append(plugins_dir)
    return plugins_dirs


def get_plugin_read_dirs(
    user_plugins_dir: Optional[Path] = None,
) -> Tuple[List[Path], Set[Path]]:
    """Return the plugin dirs in precedence order and the secondary system dirs.

    - Root: machine-wide dirs, then root's own per-user dir (legacy installs).
    - Others: their own dir, then the machine-wide ones.
    """
    system = get_system_plugins_dirs()
    user = user_plugins_dir if user_plugins_dir is not None else get_plugins_dir()
    dirs = [*system, user] if is_root() else [user, *system]
    return list(dict.fromkeys(dirs)), set(system[1:]) - {user}


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
