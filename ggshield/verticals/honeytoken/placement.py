"""
Vocabulary shared by the honeytoken placement backends (``aws_profile``,
``kubeconfig_file``): how a write or remove went, and the two ways it can refuse.

The backends are siblings — neither imports the other; ``cmd.honeytoken.plant`` only
needs these names to classify outcomes, whatever the decoy type.
"""

from __future__ import annotations

import enum
from pathlib import Path


class WriteOutcome(enum.Enum):
    WROTE = enum.auto()
    ALREADY_CURRENT = enum.auto()


class RemoveOutcome(enum.Enum):
    REMOVED = enum.auto()
    ALREADY_ABSENT = enum.auto()
    FOREIGN_KEPT = enum.auto()


class PlacementError(Exception):
    """The deployment can't be materialized (bad filename, unsupported method, unsafe
    or unparseable file)."""


def leaf_path(home: Path, directory: str, filename: str) -> Path:
    """Compose ``<home>/<directory>/<filename>``, re-asserting the server's safe-charset
    rule on the basename (defense in depth: this may run as root) so the path stays
    directly inside the backend's directory."""
    if filename in ("", ".", "..") or "/" in filename or "\\" in filename:
        raise PlacementError(f"invalid honeytoken filename {filename!r}")
    return home / directory / filename


class ForceRefusal(Exception):
    """An entry with our name exists with different content; refusing to overwrite
    without ``--force``. Each backend words the message for its own file format; the
    caller only needs the class to classify the failure as a foreign collision."""

    def __init__(self, message: str, *, name: str, path: Path) -> None:
        super().__init__(message)
        self.name = name
        self.path = path
