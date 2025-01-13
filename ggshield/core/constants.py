import os
from enum import Enum
from typing import Any

from ggshield.utils.os import getenv_int


CPU_COUNT = os.cpu_count() or 1


def _get_max_workers() -> int:
    # We add a max value to avoid silently consuming all threads on powerful machines
    return getenv_int("GG_MAX_WORKERS", 32)


MAX_WORKERS = min(CPU_COUNT, _get_max_workers())

DEFAULT_CONFIG_FILENAME = ".gitguardian.yaml"
USER_CONFIG_FILENAMES = [".gitguardian", ".gitguardian.yml", DEFAULT_CONFIG_FILENAME]
DEFAULT_INSTANCE_URL = "https://dashboard.gitguardian.com"
DEFAULT_HMSL_URL = "https://api.hasmysecretleaked.com"
AUTH_CONFIG_FILENAME = "auth_config.yaml"
ON_PREMISE_API_URL_PATH_PREFIX = "/exposed"

# These do not use pathlib.Path because of issues with pyfakefs. See:
# https://github.com/pytest-dev/pyfakefs/discussions/657
CACHE_PATH = os.path.join(".", ".cache_ggshield")
DEFAULT_LOCAL_CONFIG_PATH = os.path.join(".", DEFAULT_CONFIG_FILENAME)


class IncidentStatus(str, Enum):
    DETECTED = "detected"


class IncidentSeverity(str, Enum):
    MALICIOUS = "malicious"
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

    def _weight(self) -> int:
        """returns a weight to define `__lt__` method"""
        if self == IncidentSeverity.MALICIOUS:
            return -10
        if self == IncidentSeverity.CRITICAL:
            return 0
        if self == IncidentSeverity.HIGH:
            return 10
        if self == IncidentSeverity.MEDIUM:
            return 20
        if self == IncidentSeverity.LOW:
            return 30
        return 100

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, IncidentSeverity):
            return NotImplemented
        return self._weight() < other._weight()
