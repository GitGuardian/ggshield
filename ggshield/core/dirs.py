from appdirs import user_cache_dir, user_config_dir


APPNAME = "ggshield"
APPAUTHOR = "GitGuardian"


def get_config_dir() -> str:
    return user_config_dir(appname=APPNAME, appauthor=APPAUTHOR)


def get_cache_dir() -> str:
    return user_cache_dir(appname=APPNAME, appauthor=APPAUTHOR)
