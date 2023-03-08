import os

from appdirs import user_cache_dir, user_config_dir


APPNAME = "ggshield"
APPAUTHOR = "GitGuardian"


def get_config_dir() -> str:
    try:
        # See tests/conftest.py for details
        return os.environ["TEST_CONFIG_DIR"]
    except KeyError:
        return user_config_dir(appname=APPNAME, appauthor=APPAUTHOR)


def get_cache_dir() -> str:
    return user_cache_dir(appname=APPNAME, appauthor=APPAUTHOR)
