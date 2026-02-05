"""
Wheel utilities - extract metadata from wheel files.
"""

import email.parser
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from zipfile import BadZipFile, ZipFile


class WheelError(Exception):
    """Error processing wheel file."""

    pass


class InvalidWheelError(WheelError):
    """Wheel file is invalid or corrupted."""

    pass


class MetadataNotFoundError(WheelError):
    """METADATA file not found in wheel."""

    pass


@dataclass
class WheelMetadata:
    """Metadata extracted from a wheel file."""

    name: str
    version: str
    summary: Optional[str] = None
    author: Optional[str] = None
    license: Optional[str] = None


def extract_wheel_metadata(wheel_path: Path) -> WheelMetadata:
    """
    Extract metadata from a wheel file.

    Reads the METADATA file from the wheel's dist-info directory.

    Args:
        wheel_path: Path to the wheel file.

    Returns:
        WheelMetadata with name, version, and optional fields.

    Raises:
        InvalidWheelError: If the wheel is not a valid ZIP file.
        MetadataNotFoundError: If METADATA file is not found.
        WheelError: For other parsing errors.
    """
    if not wheel_path.exists():
        raise InvalidWheelError(f"Wheel file not found: {wheel_path}")

    if not wheel_path.suffix == ".whl":
        raise InvalidWheelError(f"Not a wheel file: {wheel_path}")

    try:
        with ZipFile(wheel_path, "r") as zf:
            metadata_path = _find_metadata_file(zf)
            if metadata_path is None:
                raise MetadataNotFoundError(
                    f"METADATA file not found in wheel: {wheel_path}"
                )

            metadata_content = zf.read(metadata_path).decode("utf-8")
            return _parse_metadata(metadata_content)

    except BadZipFile as e:
        raise InvalidWheelError(f"Invalid wheel file (not a valid ZIP): {e}") from e


def _find_metadata_file(zf: ZipFile) -> Optional[str]:
    """Find the METADATA file within a wheel's dist-info directory."""
    # Pattern: {name}-{version}.dist-info/METADATA
    for name in zf.namelist():
        if re.match(r"[^/]+-[^/]+\.dist-info/METADATA$", name):
            return name
    return None


def _parse_metadata(content: str) -> WheelMetadata:
    """Parse METADATA file content (RFC 822 format)."""
    parser = email.parser.Parser()
    msg = parser.parsestr(content)

    name = msg.get("Name")
    version = msg.get("Version")

    if not name:
        raise WheelError("METADATA missing required 'Name' field")
    if not version:
        raise WheelError("METADATA missing required 'Version' field")

    return WheelMetadata(
        name=name,
        version=version,
        summary=msg.get("Summary"),
        author=msg.get("Author"),
        license=msg.get("License"),
    )


def validate_wheel_file(wheel_path: Path) -> bool:
    """
    Validate that a file is a valid wheel.

    Returns True if the file is a valid wheel, False otherwise.
    Does not raise exceptions.
    """
    try:
        extract_wheel_metadata(wheel_path)
        return True
    except WheelError:
        return False
