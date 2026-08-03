"""
Protocols for SecretScanner and its results,
so that other verticals can use the scanner if they are provided one.
"""

from collections.abc import Mapping, Sequence
from typing import Any, Iterable, Optional, Protocol

from pygitguardian import GGClient
from pygitguardian.models import Match

from ggshield.core.scanner_ui import ScannerUI

from . import Scannable


class SecretProtocol(Protocol):
    """Abstract base class for secrets.

    We use getters instead of properties to have a .
    """

    @property
    def detector_display_name(self) -> str: ...

    @property
    def validity(self) -> str: ...

    @property
    def known_secret(self) -> bool: ...

    @property
    def incident_url(self) -> Optional[str]: ...

    @property
    def matches(self) -> Sequence[Match]: ...


class ResultProtocol(Protocol):
    @property
    def secrets(self) -> Sequence[SecretProtocol]: ...

    @property
    def ignored_secrets_count_by_kind(self) -> Mapping[Any, int]:
        """Secrets the API reported but ggshield filtered out locally. Non-empty
        means `secrets` reflects the local configuration, not just the API."""
        ...


class ResultsProtocol(Protocol):
    @property
    def results(self) -> Sequence[ResultProtocol]: ...


class ScannerProtocol(Protocol):
    """Protocol for scanners."""

    @property
    def client(self) -> GGClient: ...

    def scan(
        self,
        files: Iterable[Scannable],
        scanner_ui: ScannerUI,
        scan_threads: Optional[int] = None,
    ) -> ResultsProtocol: ...
