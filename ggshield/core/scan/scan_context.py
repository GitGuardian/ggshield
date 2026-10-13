import platform
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Union

from ggshield import __version__
from ggshield.core.git_hooks.ci.repository import get_repository_url_from_ci
from ggshield.core.machine_id import (
    _get_hostname,
    _get_machine_id,
    _get_username,
    endpoint_registration_opt_out,
    running_on_ci,
)
from ggshield.utils.git_shell import get_repository_url_from_path
from ggshield.utils.os import get_os_info

from .scan_mode import ScanMode


@dataclass
class ScanContext:
    scan_mode: Union[ScanMode, str]
    command_path: str
    extra_headers: Optional[Dict[str, str]] = None
    target_path: Optional[Path] = None
    # The user config's `endpoint_registration`, passed by the git and AI hook
    # commands only: the server registers the users of hook scans from the hostname.
    endpoint_registration: bool = False

    def __post_init__(self) -> None:
        self.command_id = str(uuid.uuid4())
        self.os_name, self.os_version = get_os_info()
        self.python_version = platform.python_version()

    def _get_repository_url(
        self,
    ) -> Optional[str]:
        repo_url = None
        if self.scan_mode == ScanMode.CI:
            repo_url = get_repository_url_from_ci()
        if repo_url is None and self.target_path is not None:
            repo_url = get_repository_url_from_path(self.target_path)
        return repo_url

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
            "Machine-Id": _get_machine_id(),
            "Machine-Username": _get_username(),
        }
        if (
            endpoint_registration_opt_out(self.endpoint_registration) is None
            and not running_on_ci()
        ):
            hostname = _get_hostname()
            # requests raises on a header value that latin-1 cannot encode.
            if _encodes_to_latin1(hostname):
                headers["Machine-Hostname"] = hostname
        repo_url = self._get_repository_url()
        if repo_url is not None:
            headers["Repository-URL"] = repo_url
        if self.extra_headers:
            headers = {**headers, **self.extra_headers}

        return {
            **{f"GGShield-{key}": str(value) for key, value in headers.items()},
            "mode": (
                self.scan_mode.value
                if isinstance(self.scan_mode, ScanMode)
                else self.scan_mode
            ),
        }


def _encodes_to_latin1(value: str) -> bool:
    try:
        value.encode("latin-1")
    except UnicodeEncodeError:
        return False
    return True
