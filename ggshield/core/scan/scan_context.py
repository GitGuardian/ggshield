import logging
import platform
import sys
import uuid
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

from ggshield import __version__

from .scan_mode import ScanMode


logger = logging.getLogger(__name__)


@lru_cache(None)
def get_os_info() -> Tuple[str, str]:
    if sys.platform.lower() == "linux":
        return parse_os_release(Path("/etc/os-release"))
    else:
        return platform.system().lower(), platform.version()


def parse_os_release(os_release_path: Path) -> Tuple[str, str]:
    """
    Extract and return Linux's OS-name and OS-Version
    If extraction fails, we return ('linux', 'unknown')
    """
    error_tuple = "linux", "unknown"

    try:
        with open(os_release_path) as f:
            lines = f.readlines()

        # Build a dictionary from the os-release file contents
        data_dict = {}
        for line in lines:
            if "=" in line:
                key, value = line.split("=")
                key, value = key.strip(), value.strip()
                data_dict[key] = value.strip('"')

        if "ID" not in data_dict:
            return error_tuple

        return data_dict["ID"], data_dict.get("VERSION_ID", "unknown")
    except Exception as exc:
        logger.warning(f"Failed to read Linux OS name and version: {exc}")
        return error_tuple


@dataclass
class ScanContext:
    scan_mode: Union[ScanMode, str]
    command_path: str
    extra_headers: Optional[Dict[str, str]] = None

    def __post_init__(self) -> None:
        self.command_id = str(uuid.uuid4())
        self.os_name, self.os_version = get_os_info()
        self.python_version = platform.python_version()

    def get_http_headers(self) -> Dict[str, str]:
        """
        Returns the extra headers to send in HTTP requests.
        If `command_id` is not None, a `GGShield-Command-Id` header will be sent.
        Adds the "GGShield-" prefix to the header's names.
        """
        headers = {
            "Version": __version__,
            "Command-Path": self.command_path,
            "Command-Id": self.command_id,
            "OS-Name": self.os_name,
            "OS-Version": self.os_version,
            "Python-Version": self.python_version,
        }
        if self.extra_headers:
            headers = {**headers, **self.extra_headers}

        return {
            **{f"GGShield-{key}": str(value) for key, value in headers.items()},
            "mode": self.scan_mode.value
            if isinstance(self.scan_mode, ScanMode)
            else self.scan_mode,
        }
