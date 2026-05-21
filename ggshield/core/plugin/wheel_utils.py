"""
Wheel utilities - extract metadata from wheel files.
"""

import email.parser
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
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


def sanitize_wheel_filename(raw: str) -> str:
    """Return a wheel filename safe to use as a single path segment.

    Strips path components the server may have included and rejects
    values that would resolve outside the plugin directory (``..``,
    empty segment, embedded NUL, backslash, Windows drive-qualified
    or UNC-prefixed paths). Requires a ``.whl`` suffix.

    Raises:
        InvalidWheelError: when the input doesn't satisfy the rules.
    """
    name = PurePosixPath(raw).name
    # Reject backslash and colon as well as posix path tricks: on
    # Windows, ``Path("plugins") / "D:evil.whl"`` resolves drive-
    # relative and escapes the plugins directory; ``\\?\C:\...`` and
    # ``\\share\...`` have the same effect. ``PurePosixPath`` doesn't
    # strip those, so we filter explicitly here.
    if not name or name in {".", ".."} or "\x00" in name or "\\" in name or ":" in name:
        raise InvalidWheelError(f"Server returned unsafe filename: {raw!r}")
    if not name.endswith(".whl"):
        raise InvalidWheelError(f"Wheel filename must end in .whl: {raw!r}")
    return name
