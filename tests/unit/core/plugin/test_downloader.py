"""Tests for plugin downloader."""

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from ggshield.core.plugin.client import PluginDownloadInfo
from ggshield.core.plugin.downloader import (
    ChecksumMismatchError,
    DownloadError,
    PluginDownloader,
    get_plugins_dir,
)


class TestPluginDownloader:
    """Tests for PluginDownloader."""

    def test_init(self, tmp_path: Path) -> None:
        """Test downloader initialization."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.plugins_dir == tmp_path

    def test_is_installed_false(self, tmp_path: Path) -> None:
        """Test is_installed returns False for non-installed plugin."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.is_installed("nonexistent") is False

    def test_is_installed_true(self, tmp_path: Path) -> None:
        """Test is_installed returns True for installed plugin."""
        # Create plugin directory with manifest
        plugin_dir = tmp_path / "testplugin"
        plugin_dir.mkdir()
        manifest = {
            "plugin_name": "testplugin",
            "version": "1.0.0",
            "wheel_filename": "testplugin-1.0.0.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.is_installed("testplugin") is True

    def test_get_installed_version_not_installed(self, tmp_path: Path) -> None:
        """Test get_installed_version for non-installed plugin."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.get_installed_version("nonexistent") is None

    def test_get_installed_version(self, tmp_path: Path) -> None:
        """Test get_installed_version for installed plugin."""
        # Create plugin directory with manifest
        plugin_dir = tmp_path / "testplugin"
        plugin_dir.mkdir()
        manifest = {
            "plugin_name": "testplugin",
            "version": "1.2.3",
            "wheel_filename": "testplugin-1.2.3.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.get_installed_version("testplugin") == "1.2.3"

    def test_get_wheel_path_not_installed(self, tmp_path: Path) -> None:
        """Test get_wheel_path for non-installed plugin."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.get_wheel_path("nonexistent") is None

    def test_get_wheel_path(self, tmp_path: Path) -> None:
        """Test get_wheel_path for installed plugin."""
        # Create plugin directory with manifest and wheel
        plugin_dir = tmp_path / "testplugin"
        plugin_dir.mkdir()
        wheel_path = plugin_dir / "testplugin-1.0.0.whl"
        wheel_path.touch()
        manifest = {
            "plugin_name": "testplugin",
            "version": "1.0.0",
            "wheel_filename": "testplugin-1.0.0.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.get_wheel_path("testplugin") == wheel_path

    def test_uninstall_not_installed(self, tmp_path: Path) -> None:
        """Test uninstall returns False for non-installed plugin."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.uninstall("nonexistent") is False

    def test_uninstall(self, tmp_path: Path) -> None:
        """Test uninstall removes plugin directory."""
        # Create plugin directory
        plugin_dir = tmp_path / "testplugin"
        plugin_dir.mkdir()
        (plugin_dir / "manifest.json").write_text("{}")
        (plugin_dir / "testplugin.whl").touch()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.uninstall("testplugin") is True
        assert not plugin_dir.exists()

    def test_download_and_install_success(self, tmp_path: Path) -> None:
        """Test successful download and install."""
        wheel_content = b"fake wheel content"
        sha256 = hashlib.sha256(wheel_content).hexdigest()

        download_info = PluginDownloadInfo(
            download_url="https://example.com/plugin.whl",
            filename="testplugin-1.0.0.whl",
            sha256=sha256,
            version="1.0.0",
            expires_at="2025-01-01T00:00:00Z",
        )

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [wheel_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            with patch("requests.get", return_value=mock_response):
                downloader = PluginDownloader()
                wheel_path = downloader.download_and_install(
                    download_info, "testplugin"
                )

        assert wheel_path.exists()
        assert wheel_path.name == "testplugin-1.0.0.whl"
        assert (tmp_path / "testplugin" / "manifest.json").exists()

        # Verify manifest content
        manifest = json.loads((tmp_path / "testplugin" / "manifest.json").read_text())
        assert manifest["plugin_name"] == "testplugin"
        assert manifest["version"] == "1.0.0"

    def test_download_and_install_checksum_mismatch(self, tmp_path: Path) -> None:
        """Test download fails with checksum mismatch."""
        wheel_content = b"fake wheel content"
        wrong_sha256 = "0" * 64  # Wrong checksum

        download_info = PluginDownloadInfo(
            download_url="https://example.com/plugin.whl",
            filename="testplugin-1.0.0.whl",
            sha256=wrong_sha256,
            version="1.0.0",
            expires_at="2025-01-01T00:00:00Z",
        )

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [wheel_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            with patch("requests.get", return_value=mock_response):
                downloader = PluginDownloader()

                with pytest.raises(ChecksumMismatchError):
                    downloader.download_and_install(download_info, "testplugin")

    def test_download_and_install_network_error(self, tmp_path: Path) -> None:
        """Test download fails with network error."""
        download_info = PluginDownloadInfo(
            download_url="https://example.com/plugin.whl",
            filename="testplugin-1.0.0.whl",
            sha256="abc123",
            version="1.0.0",
            expires_at="2025-01-01T00:00:00Z",
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            with patch(
                "requests.get", side_effect=requests.RequestException("Network error")
            ):
                downloader = PluginDownloader()

                with pytest.raises(DownloadError) as exc_info:
                    downloader.download_and_install(download_info, "testplugin")

                assert "Failed to download plugin" in str(exc_info.value)


class TestChecksumMismatchError:
    """Tests for ChecksumMismatchError."""

    def test_error_message(self) -> None:
        """Test error message formatting."""
        error = ChecksumMismatchError(
            expected="abcdef1234567890" * 4, actual="0987654321fedcba" * 4
        )

        assert "abcdef1234567890" in str(error)
        assert "0987654321fedcba" in str(error)
        assert "Checksum mismatch" in str(error)


class TestGetPluginsDir:
    """Tests for get_plugins_dir function."""

    @patch("ggshield.core.plugin.downloader.get_data_dir")
    def test_creates_directory(self, mock_data_dir: MagicMock, tmp_path: Path) -> None:
        """Test that get_plugins_dir creates the directory if it doesn't exist."""
        plugins_path = tmp_path / "plugins"
        mock_data_dir.return_value = tmp_path

        result = get_plugins_dir()

        assert result == plugins_path
        assert plugins_path.exists()
