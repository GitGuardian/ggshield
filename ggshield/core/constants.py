import os
from enum import Enum


CPU_COUNT = os.cpu_count() or 1


def _get_max_workers() -> int:
    # We add a max value to avoid silently consuming all threads on powerful machines
    return int(os.getenv("GG_MAX_WORKERS", "32"))


MAX_WORKERS = min(CPU_COUNT, _get_max_workers())
CACHE_FILENAME = "./.cache_ggshield"
DEFAULT_CONFIG_FILENAME = ".gitguardian.yaml"
USER_CONFIG_FILENAMES = [".gitguardian", ".gitguardian.yml", DEFAULT_CONFIG_FILENAME]
DEFAULT_LOCAL_CONFIG_PATH = os.path.join(".", DEFAULT_CONFIG_FILENAME)
DEFAULT_INSTANCE_URL = "https://dashboard.gitguardian.com"
DEFAULT_HMSL_URL = "https://api.hasmysecretleaked.com"
AUTH_CONFIG_FILENAME = "auth_config.yaml"
ON_PREMISE_API_URL_PATH_PREFIX = "/exposed"


class IncidentStatus(str, Enum):
    DETECTED = "detected"
    REMOVED = "removed"
