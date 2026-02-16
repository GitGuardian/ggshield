"""Tests for platform detection utilities."""

import sys
from unittest.mock import patch

from ggshield.core.plugin.platform import (
    PlatformInfo,
    format_platform_tag,
    get_platform_info,
    get_wheel_platform_tags,
)


class TestPlatformInfo:
    """Tests for PlatformInfo dataclass."""

    def test_platform_info_creation(self) -> None:
        """Test creating PlatformInfo."""
        info = PlatformInfo(os="linux", arch="x86_64", python_abi="cp311")

        assert info.os == "linux"
        assert info.arch == "x86_64"
        assert info.python_abi == "cp311"


class TestGetPlatformInfo:
    """Tests for get_platform_info function."""

    def test_get_platform_info_returns_platform_info(self) -> None:
        """Test that get_platform_info returns PlatformInfo."""
        info = get_platform_info()

        assert isinstance(info, PlatformInfo)
        assert info.os in ("macosx", "linux", "win")
        assert info.arch in ("arm64", "x86_64", "aarch64", "amd64")
        assert info.python_abi.startswith("cp")

    @patch("platform.system")
    def test_detect_macos(self, mock_system: object) -> None:
        """Test detecting macOS."""
        mock_system.return_value = "Darwin"  # type: ignore[union-attr]

        info = get_platform_info()

        assert info.os == "macosx"

    @patch("platform.system")
    def test_detect_linux(self, mock_system: object) -> None:
        """Test detecting Linux."""
        mock_system.return_value = "Linux"  # type: ignore[union-attr]

        info = get_platform_info()

        assert info.os == "linux"

    @patch("platform.system")
    def test_detect_windows(self, mock_system: object) -> None:
        """Test detecting Windows."""
        mock_system.return_value = "Windows"  # type: ignore[union-attr]

        info = get_platform_info()

        assert info.os == "win"

    @patch("platform.machine")
    def test_detect_arm64(self, mock_machine: object) -> None:
        """Test detecting arm64 architecture."""
        mock_machine.return_value = "arm64"  # type: ignore[union-attr]

        info = get_platform_info()

        assert info.arch == "arm64"

    @patch("platform.machine")
    def test_detect_aarch64(self, mock_machine: object) -> None:
        """Test detecting aarch64 architecture (normalized to arm64)."""
        mock_machine.return_value = "aarch64"  # type: ignore[union-attr]

        info = get_platform_info()

        assert info.arch == "arm64"

    @patch("platform.machine")
    def test_detect_x86_64(self, mock_machine: object) -> None:
        """Test detecting x86_64 architecture."""
        mock_machine.return_value = "x86_64"  # type: ignore[union-attr]

        info = get_platform_info()

        assert info.arch == "x86_64"

    def test_python_abi(self) -> None:
        """Test Python ABI detection."""
        info = get_platform_info()
        expected_abi = f"cp{sys.version_info.major}{sys.version_info.minor}"

        assert info.python_abi == expected_abi


class TestFormatPlatformTag:
    """Tests for format_platform_tag function."""

    def test_format_tag(self) -> None:
        """Test formatting platform tag."""
        info = PlatformInfo(os="linux", arch="x86_64", python_abi="cp311")

        tag = format_platform_tag(info)

        assert tag == "linux-x86_64"

    def test_format_macos_arm64(self) -> None:
        """Test formatting macOS arm64 tag."""
        info = PlatformInfo(os="macosx", arch="arm64", python_abi="cp311")

        tag = format_platform_tag(info)

        assert tag == "macosx-arm64"


class TestGetWheelPlatformTags:
    """Tests for get_wheel_platform_tags function."""

    @patch("ggshield.core.plugin.platform.get_platform_info")
    def test_returns_list_of_tags(self, mock_info: object) -> None:
        """Test that function returns a list of tags."""
        mock_info.return_value = PlatformInfo(  # type: ignore[union-attr]
            os="linux", arch="x86_64", python_abi="cp311"
        )

        tags = get_wheel_platform_tags()

        assert isinstance(tags, list)
        assert len(tags) >= 1
        assert "linux-x86_64" in tags

    @patch("ggshield.core.plugin.platform.get_platform_info")
    def test_arm64_includes_aarch64_alias(self, mock_info: object) -> None:
        """Test that arm64 includes aarch64 as alias."""
        mock_info.return_value = PlatformInfo(  # type: ignore[union-attr]
            os="linux", arch="arm64", python_abi="cp311"
        )

        tags = get_wheel_platform_tags()

        assert "linux-arm64" in tags
        assert "linux-aarch64" in tags

    @patch("ggshield.core.plugin.platform.get_platform_info")
    def test_x86_64_includes_amd64_alias(self, mock_info: object) -> None:
        """Test that x86_64 includes amd64 as alias."""
        mock_info.return_value = PlatformInfo(  # type: ignore[union-attr]
            os="win", arch="x86_64", python_abi="cp311"
        )

        tags = get_wheel_platform_tags()

        assert "win-x86_64" in tags
        assert "win-amd64" in tags
