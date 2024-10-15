import os
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


def get_project_root_dir(path: Path) -> Path:
    """
    Returns the source basedir required to find file within filesystem.
    """
    try:
        return get_git_root(wd=path).resolve()
    except NotAGitDirectory:
        # In case we are not in a Git repository
        return path.resolve()
