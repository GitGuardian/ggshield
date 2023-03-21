import os


CPU_COUNT = os.cpu_count() or 1


def _get_max_workers() -> int:
    # We add a max value to avoid silently consuming all threads on powerful machines
    return int(os.getenv("GG_MAX_WORKERS", "32"))


MAX_WORKERS = min(CPU_COUNT, _get_max_workers())
CACHE_FILENAME = "./.cache_ggshield"
GLOBAL_CONFIG_FILENAMES = [".gitguardian", ".gitguardian.yml", ".gitguardian.yaml"]
LOCAL_CONFIG_PATHS = ["./.gitguardian", "./.gitguardian.yml", "./.gitguardian.yaml"]
DEFAULT_LOCAL_CONFIG_PATH = "./.gitguardian.yaml"
DEFAULT_INSTANCE_URL = "https://dashboard.gitguardian.com"
AUTH_CONFIG_FILENAME = "auth_config.yaml"
ON_PREMISE_API_URL_PATH_PREFIX = "/exposed"
