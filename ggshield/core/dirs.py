import os
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
    """Machine-wide (all users) config dir, e.g. for the service-account token.

    Used when ``machine setup`` provisions a fleet/MDM service-account token that
    every account on the machine falls back to.
    """
    try:
        return Path(os.environ["GG_SYSTEM_CONFIG_DIR"])
    except KeyError:
        return Path(site_config_dir(appname=APPNAME, appauthor=APPAUTHOR))


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
