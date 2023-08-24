import platform
import uuid
from dataclasses import dataclass
from typing import Dict, Optional, Union

from ggshield import __version__
from ggshield.utils.os import get_os_info

from .scan_mode import ScanMode


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
