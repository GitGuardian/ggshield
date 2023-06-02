import os
from typing import Any

from appdirs import user_cache_dir, user_config_dir


APPNAME = "ggshield"
APPAUTHOR = "GitGuardian"


def get_config_dir() -> Any:
    try:
        # See tests/conftest.py for details
        return str(os.environ["GG_CONFIG_DIR"])
    except KeyError:
        return user_config_dir(appname=APPNAME, appauthor=APPAUTHOR)


def get_cache_dir() -> Any:
    try:
        # See tests/conftest.py for details
        return str(os.environ["GG_CACHE_DIR"])
    except KeyError:
        return user_cache_dir(appname=APPNAME, appauthor=APPAUTHOR)
