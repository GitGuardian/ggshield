"""Tests for wheel utilities."""

import zipfile
from pathlib import Path
from typing import Optional

import pytest

from ggshield.core.plugin.wheel_utils import (
    InvalidWheelError,
    MetadataNotFoundError,
    WheelError,
    WheelMetadata,
    extract_wheel_metadata,
    validate_wheel_file,
)


def create_test_wheel(
    tmp_path: Path,
    name: str = "testplugin",
    version: str = "1.0.0",
    include_metadata: bool = True,
    metadata_content: Optional[str] = None,
) -> Path:
    """Create a test wheel file."""
    wheel_name = f"{name}-{version}-py3-none-any.whl"
    wheel_path = tmp_path / wheel_name

    with zipfile.ZipFile(wheel_path, "w") as zf:
        if include_metadata:
            dist_info = f"{name}-{version}.dist-info"
            if metadata_content is None:
                metadata_content = f"""Metadata-Version: 2.1
Name: {name}
Version: {version}
Summary: A test plugin
Author: Test Author
License: MIT
"""
            zf.writestr(f"{dist_info}/METADATA", metadata_content)
            zf.writestr(f"{dist_info}/WHEEL", "Wheel-Version: 1.0")
            zf.writestr(f"{dist_info}/RECORD", "")

        # Add a dummy module
        zf.writestr(f"{name}/__init__.py", "# Test module")

    return wheel_path


class TestExtractWheelMetadata:
    """Tests for extract_wheel_metadata function."""

    def test_extract_valid_wheel(self, tmp_path: Path) -> None:
        """Test extracting metadata from a valid wheel."""
        wheel_path = create_test_wheel(tmp_path, "myplugin", "2.3.4")

        metadata = extract_wheel_metadata(wheel_path)

        assert metadata.name == "myplugin"
        assert metadata.version == "2.3.4"
        assert metadata.summary == "A test plugin"
        assert metadata.author == "Test Author"
        assert metadata.license == "MIT"

    def test_extract_minimal_metadata(self, tmp_path: Path) -> None:
        """Test extracting minimal metadata (only name and version)."""
        minimal_metadata = """Metadata-Version: 2.1
Name: minimal-plugin
Version: 0.1.0
"""
        wheel_path = create_test_wheel(
            tmp_path,
            "minimal-plugin",
            "0.1.0",
            metadata_content=minimal_metadata,
        )

        metadata = extract_wheel_metadata(wheel_path)

        assert metadata.name == "minimal-plugin"
        assert metadata.version == "0.1.0"
        assert metadata.summary is None
        assert metadata.author is None

    def test_wheel_not_found(self, tmp_path: Path) -> None:
        """Test error when wheel file doesn't exist."""
        nonexistent = tmp_path / "nonexistent.whl"

        with pytest.raises(InvalidWheelError) as exc_info:
            extract_wheel_metadata(nonexistent)

        assert "not found" in str(exc_info.value)

    def test_not_a_wheel_file(self, tmp_path: Path) -> None:
        """Test error when file doesn't have .whl extension."""
        not_wheel = tmp_path / "file.txt"
        not_wheel.write_text("not a wheel")

        with pytest.raises(InvalidWheelError) as exc_info:
            extract_wheel_metadata(not_wheel)

        assert "Not a wheel file" in str(exc_info.value)

    def test_invalid_zip_file(self, tmp_path: Path) -> None:
        """Test error when file is not a valid ZIP."""
        invalid_wheel = tmp_path / "invalid.whl"
        invalid_wheel.write_bytes(b"not a zip file")

        with pytest.raises(InvalidWheelError) as exc_info:
            extract_wheel_metadata(invalid_wheel)

        assert "not a valid ZIP" in str(exc_info.value)

    def test_missing_metadata_file(self, tmp_path: Path) -> None:
        """Test error when METADATA file is missing."""
        wheel_path = create_test_wheel(
            tmp_path,
            include_metadata=False,
        )

        with pytest.raises(MetadataNotFoundError) as exc_info:
            extract_wheel_metadata(wheel_path)

        assert "METADATA file not found" in str(exc_info.value)

    def test_missing_name_field(self, tmp_path: Path) -> None:
        """Test error when Name field is missing."""
        bad_metadata = """Metadata-Version: 2.1
Version: 1.0.0
"""
        wheel_path = create_test_wheel(
            tmp_path,
            metadata_content=bad_metadata,
        )

        with pytest.raises(WheelError) as exc_info:
            extract_wheel_metadata(wheel_path)

        assert "Name" in str(exc_info.value)

    def test_missing_version_field(self, tmp_path: Path) -> None:
        """Test error when Version field is missing."""
        bad_metadata = """Metadata-Version: 2.1
Name: myplugin
"""
        wheel_path = create_test_wheel(
            tmp_path,
            metadata_content=bad_metadata,
        )

        with pytest.raises(WheelError) as exc_info:
            extract_wheel_metadata(wheel_path)

        assert "Version" in str(exc_info.value)


class TestValidateWheelFile:
    """Tests for validate_wheel_file function."""

    def test_valid_wheel(self, tmp_path: Path) -> None:
        """Test validation of a valid wheel."""
        wheel_path = create_test_wheel(tmp_path)

        assert validate_wheel_file(wheel_path) is True

    def test_invalid_wheel(self, tmp_path: Path) -> None:
        """Test validation of an invalid wheel."""
        invalid_wheel = tmp_path / "invalid.whl"
        invalid_wheel.write_bytes(b"not a zip")

        assert validate_wheel_file(invalid_wheel) is False

    def test_missing_wheel(self, tmp_path: Path) -> None:
        """Test validation of a non-existent file."""
        nonexistent = tmp_path / "nonexistent.whl"

        assert validate_wheel_file(nonexistent) is False


class TestWheelMetadata:
    """Tests for WheelMetadata dataclass."""

    def test_dataclass_fields(self) -> None:
        """Test WheelMetadata can be created with all fields."""
        metadata = WheelMetadata(
            name="test",
            version="1.0.0",
            summary="A summary",
            author="Author",
            license="MIT",
        )

        assert metadata.name == "test"
        assert metadata.version == "1.0.0"
        assert metadata.summary == "A summary"
        assert metadata.author == "Author"
        assert metadata.license == "MIT"

    def test_optional_fields_default_none(self) -> None:
        """Test optional fields default to None."""
        metadata = WheelMetadata(name="test", version="1.0.0")

        assert metadata.summary is None
        assert metadata.author is None
        assert metadata.license is None
