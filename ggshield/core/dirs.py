import os
import sys
from pathlib import Path

from platformdirs import user_cache_dir, user_config_dir, user_data_dir

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


def get_plugins_dir(*, create: bool = False) -> Path:
    """Return the plugin directory inside the ggshield data directory."""
    plugins_dir = get_data_dir() / "plugins"
    if create:
        plugins_dir.mkdir(parents=True, exist_ok=True)
    return plugins_dir


def get_project_root_dir(path: Path) -> Path:
    """
    Returns the source basedir required to find file within filesystem.
    """
    try:
        return get_git_root(wd=path).resolve()
    except NotAGitDirectory:
        # In case we are not in a Git repository
        return path.resolve()
