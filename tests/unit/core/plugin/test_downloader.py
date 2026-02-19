"""Tests for plugin downloader."""

import hashlib
import json
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from ggshield.core.plugin.client import (
    PluginDownloadInfo,
    PluginSource,
    PluginSourceType,
)
from ggshield.core.plugin.downloader import (
    ChecksumMismatchError,
    DownloadError,
    GitHubArtifactError,
    InsecureSourceError,
    PluginDownloader,
    get_plugins_dir,
)
from ggshield.core.plugin.signature import SignatureInfo, SignatureStatus


MOCK_SIG_INFO = SignatureInfo(status=SignatureStatus.SKIPPED)


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
                with patch(
                    "ggshield.core.plugin.downloader.verify_wheel_signature",
                    return_value=MOCK_SIG_INFO,
                ):
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

    def test_download_and_install_rejects_invalid_plugin_name(
        self, tmp_path: Path
    ) -> None:
        """Test install rejects unsafe plugin names."""
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
            with patch("requests.get") as mock_get:
                downloader = PluginDownloader()

                with pytest.raises(DownloadError) as exc_info:
                    downloader.download_and_install(download_info, "../../outside")

                assert "Invalid plugin name" in str(exc_info.value)
                mock_get.assert_not_called()

    def test_download_and_install_manifest_failure_cleans_temp_file(
        self, tmp_path: Path
    ) -> None:
        """Test temp file is cleaned up if manifest write fails."""
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
                with patch(
                    "ggshield.core.plugin.downloader.verify_wheel_signature",
                    return_value=MOCK_SIG_INFO,
                ):
                    downloader = PluginDownloader()

                    with patch.object(
                        downloader, "_write_manifest", side_effect=OSError("disk full")
                    ):
                        with pytest.raises(OSError):
                            downloader.download_and_install(download_info, "testplugin")

        temp_path = tmp_path / "testplugin" / "testplugin-1.0.0.whl.tmp"
        assert not temp_path.exists()

    def test_is_installed_by_entry_point_name(self, tmp_path: Path) -> None:
        """Test is_installed finds plugin by entry point name."""
        # Create plugin with different package name than entry point name
        plugin_dir = tmp_path / "package-name"
        plugin_dir.mkdir()
        wheel_path = plugin_dir / "package_name-1.0.0.whl"

        # Create wheel with entry point named "my_plugin"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr(
                "package_name-1.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\nmy_plugin = package_name.plugin:Plugin\n",
            )

        manifest = {
            "plugin_name": "package-name",
            "version": "1.0.0",
            "wheel_filename": "package_name-1.0.0.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        # Should find by entry point name
        assert downloader.is_installed("my_plugin") is True
        # Should also find by package name
        assert downloader.is_installed("package-name") is True
        # Should not find non-existent
        assert downloader.is_installed("nonexistent") is False

    def test_get_installed_version_by_entry_point_name(self, tmp_path: Path) -> None:
        """Test get_installed_version finds plugin by entry point name."""
        # Create plugin with different package name than entry point name
        plugin_dir = tmp_path / "package-name"
        plugin_dir.mkdir()
        wheel_path = plugin_dir / "package_name-1.0.0.whl"

        # Create wheel with entry point named "my_plugin"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr(
                "package_name-1.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\nmy_plugin = package_name.plugin:Plugin\n",
            )

        manifest = {
            "plugin_name": "package-name",
            "version": "2.0.0",
            "wheel_filename": "package_name-1.0.0.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        # Should find version by entry point name
        assert downloader.get_installed_version("my_plugin") == "2.0.0"

    def test_uninstall_by_entry_point_name(self, tmp_path: Path) -> None:
        """Test uninstall can remove plugin by entry point name."""
        # Create plugin with different package name than entry point name
        plugin_dir = tmp_path / "package-name"
        plugin_dir.mkdir()
        wheel_path = plugin_dir / "package_name-1.0.0.whl"

        # Create wheel with entry point named "my_plugin"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr(
                "package_name-1.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\nmy_plugin = package_name.plugin:Plugin\n",
            )

        manifest = {
            "plugin_name": "package-name",
            "version": "1.0.0",
            "wheel_filename": "package_name-1.0.0.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        # Should uninstall by entry point name
        assert downloader.uninstall("my_plugin") is True
        assert not plugin_dir.exists()

    def test_find_plugin_dir_by_entry_point_not_found(self, tmp_path: Path) -> None:
        """Test _find_plugin_dir_by_entry_point returns None when not found."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader._find_plugin_dir_by_entry_point("nonexistent") is None

    def test_find_plugin_dir_by_entry_point_no_plugins_dir(
        self, tmp_path: Path
    ) -> None:
        """Test _find_plugin_dir_by_entry_point when plugins dir doesn't exist."""
        nonexistent_dir = tmp_path / "nonexistent"

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir",
            return_value=nonexistent_dir,
        ):
            downloader = PluginDownloader()

        assert downloader._find_plugin_dir_by_entry_point("test") is None

    def test_read_entry_point_name_from_wheel_no_entry_points(
        self, tmp_path: Path
    ) -> None:
        """Test _read_entry_point_name_from_wheel when no entry points."""
        wheel_path = tmp_path / "test-1.0.0.whl"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr("test-1.0.0.dist-info/METADATA", "Name: test\nVersion: 1.0.0\n")

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader._read_entry_point_name_from_wheel(wheel_path) is None

    def test_read_entry_point_name_from_wheel_invalid_file(
        self, tmp_path: Path
    ) -> None:
        """Test _read_entry_point_name_from_wheel with invalid file."""
        invalid_file = tmp_path / "not-a-wheel.txt"
        invalid_file.write_text("not a zip file")

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader._read_entry_point_name_from_wheel(invalid_file) is None


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

    @patch("ggshield.core.dirs.get_data_dir")
    def test_creates_directory(self, mock_data_dir: MagicMock, tmp_path: Path) -> None:
        """Test that get_plugins_dir creates the directory if it doesn't exist."""
        plugins_path = tmp_path / "plugins"
        mock_data_dir.return_value = tmp_path

        result = get_plugins_dir(create=True)

        assert result == plugins_path
        assert plugins_path.exists()


def create_test_wheel(
    tmp_path: Path, name: str = "testplugin", version: str = "1.0.0"
) -> Path:
    """Create a minimal valid wheel file for testing."""
    wheel_name = f"{name}-{version}-py3-none-any.whl"
    wheel_path = tmp_path / wheel_name

    with zipfile.ZipFile(wheel_path, "w") as zf:
        dist_info = f"{name}-{version}.dist-info"
        metadata_content = f"""Metadata-Version: 2.1
Name: {name}
Version: {version}
Summary: A test plugin
"""
        zf.writestr(f"{dist_info}/METADATA", metadata_content)
        zf.writestr(f"{dist_info}/WHEEL", "Wheel-Version: 1.0")
        zf.writestr(f"{dist_info}/RECORD", "")
        zf.writestr(f"{name}/__init__.py", "# Test module")

    return wheel_path


class TestInstallFromWheel:
    """Tests for install_from_wheel method."""

    def test_install_from_wheel_success(self, tmp_path: Path) -> None:
        """Test successful installation from a local wheel file."""
        # Create source wheel
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        wheel_path = create_test_wheel(source_dir, "myplugin", "2.0.0")

        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch(
                "ggshield.core.plugin.downloader.verify_wheel_signature",
                return_value=MOCK_SIG_INFO,
            ):
                downloader = PluginDownloader()
                plugin_name, version, installed_path = downloader.install_from_wheel(
                    wheel_path
                )

        assert plugin_name == "myplugin"
        assert version == "2.0.0"
        assert installed_path.exists()
        assert installed_path.parent == plugins_dir / "myplugin"

        # Verify manifest
        manifest = json.loads((plugins_dir / "myplugin" / "manifest.json").read_text())
        assert manifest["plugin_name"] == "myplugin"
        assert manifest["version"] == "2.0.0"
        assert manifest["source"]["type"] == "local_file"

    def test_install_from_wheel_invalid_wheel(self, tmp_path: Path) -> None:
        """Test installation fails with invalid wheel."""
        invalid_wheel = tmp_path / "invalid.whl"
        invalid_wheel.write_bytes(b"not a wheel")

        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            downloader = PluginDownloader()

            with pytest.raises(DownloadError) as exc_info:
                downloader.install_from_wheel(invalid_wheel)

            assert "Invalid wheel file" in str(exc_info.value)


class TestDownloadFromUrl:
    """Tests for download_from_url method."""

    def test_download_from_url_success(self, tmp_path: Path) -> None:
        """Test successful download from URL."""
        # Create wheel content
        wheel_dir = tmp_path / "wheel_content"
        wheel_dir.mkdir()
        wheel_path = create_test_wheel(wheel_dir, "urlplugin", "1.0.0")
        wheel_content = wheel_path.read_bytes()
        sha256 = hashlib.sha256(wheel_content).hexdigest()

        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [wheel_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                with patch(
                    "ggshield.core.plugin.downloader.verify_wheel_signature",
                    return_value=MOCK_SIG_INFO,
                ):
                    downloader = PluginDownloader()
                    plugin_name, version, installed_path = downloader.download_from_url(
                        "https://example.com/urlplugin-1.0.0.whl",
                        sha256=sha256,
                    )

        assert plugin_name == "urlplugin"
        assert version == "1.0.0"
        assert installed_path.exists()

        # Verify manifest source tracking
        manifest = json.loads((plugins_dir / "urlplugin" / "manifest.json").read_text())
        assert manifest["source"]["type"] == "url"
        assert manifest["source"]["url"] == "https://example.com/urlplugin-1.0.0.whl"

    def test_download_from_url_http_rejected(self, tmp_path: Path) -> None:
        """Test that HTTP URLs are rejected."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            downloader = PluginDownloader()

            with pytest.raises(InsecureSourceError) as exc_info:
                downloader.download_from_url("http://example.com/plugin.whl")

            assert "HTTP URLs are not allowed" in str(exc_info.value)

    def test_download_from_url_checksum_mismatch(self, tmp_path: Path) -> None:
        """Test checksum verification failure."""
        wheel_dir = tmp_path / "wheel_content"
        wheel_dir.mkdir()
        wheel_path = create_test_wheel(wheel_dir, "urlplugin", "1.0.0")
        wheel_content = wheel_path.read_bytes()

        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [wheel_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                downloader = PluginDownloader()

                with pytest.raises(ChecksumMismatchError):
                    downloader.download_from_url(
                        "https://example.com/plugin.whl",
                        sha256="0" * 64,  # Wrong checksum
                    )


class TestDownloadFromGitHubRelease:
    """Tests for download_from_github_release method."""

    def test_github_release_extracts_repo(self, tmp_path: Path) -> None:
        """Test that GitHub repo is extracted from URL."""
        wheel_dir = tmp_path / "wheel_content"
        wheel_dir.mkdir()
        wheel_path = create_test_wheel(wheel_dir, "ghplugin", "1.0.0")
        wheel_content = wheel_path.read_bytes()
        sha256 = hashlib.sha256(wheel_content).hexdigest()

        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [wheel_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                with patch(
                    "ggshield.core.plugin.downloader.verify_wheel_signature",
                    return_value=MOCK_SIG_INFO,
                ):
                    downloader = PluginDownloader()
                    plugin_name, version, _ = downloader.download_from_github_release(
                        "https://github.com/owner/repo/releases/download/v1.0.0/ghplugin-1.0.0.whl",
                        sha256=sha256,
                    )

        assert plugin_name == "ghplugin"
        assert version == "1.0.0"

        # Verify source tracking has GitHub repo
        manifest = json.loads((plugins_dir / "ghplugin" / "manifest.json").read_text())
        assert manifest["source"]["type"] == "github_release"
        assert manifest["source"]["github_repo"] == "owner/repo"


class TestDownloadFromGitHubArtifact:
    """Tests for download_from_github_artifact method."""

    def test_invalid_artifact_url(self, tmp_path: Path) -> None:
        """Test error with invalid artifact URL."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            downloader = PluginDownloader()

            with pytest.raises(GitHubArtifactError) as exc_info:
                downloader.download_from_github_artifact(
                    "https://github.com/owner/repo/invalid/url"
                )

            assert "Invalid GitHub artifact URL" in str(exc_info.value)

    def test_missing_github_token(self, tmp_path: Path) -> None:
        """Test error when no GitHub token is available."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch.dict("os.environ", {}, clear=True):
                with patch.object(PluginDownloader, "_get_gh_token", return_value=None):
                    downloader = PluginDownloader()

                    with pytest.raises(GitHubArtifactError) as exc_info:
                        downloader.download_from_github_artifact(
                            "https://github.com/owner/repo/actions/runs/123/artifacts/456"
                        )

                    assert "GitHub authentication required" in str(exc_info.value)


class TestGetPluginSource:
    """Tests for get_plugin_source method."""

    def test_get_source_gitguardian(self, tmp_path: Path) -> None:
        """Test getting source for GitGuardian API plugin."""
        plugin_dir = tmp_path / "testplugin"
        plugin_dir.mkdir()
        manifest = {
            "plugin_name": "testplugin",
            "version": "1.0.0",
            "wheel_filename": "testplugin-1.0.0.whl",
            "sha256": "abc123",
            "source": {"type": "gitguardian_api"},
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            source = downloader.get_plugin_source("testplugin")

        assert source is not None
        assert source.type == PluginSourceType.GITGUARDIAN_API

    def test_get_source_url(self, tmp_path: Path) -> None:
        """Test getting source for URL-installed plugin."""
        plugin_dir = tmp_path / "urlplugin"
        plugin_dir.mkdir()
        manifest = {
            "plugin_name": "urlplugin",
            "version": "1.0.0",
            "wheel_filename": "urlplugin-1.0.0.whl",
            "sha256": "abc123",
            "source": {
                "type": "url",
                "url": "https://example.com/plugin.whl",
            },
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            source = downloader.get_plugin_source("urlplugin")

        assert source is not None
        assert source.type == PluginSourceType.URL
        assert source.url == "https://example.com/plugin.whl"

    def test_get_source_github_release(self, tmp_path: Path) -> None:
        """Test getting source for GitHub release plugin."""
        plugin_dir = tmp_path / "ghplugin"
        plugin_dir.mkdir()
        manifest = {
            "plugin_name": "ghplugin",
            "version": "1.0.0",
            "wheel_filename": "ghplugin-1.0.0.whl",
            "sha256": "abc123",
            "source": {
                "type": "github_release",
                "url": "https://github.com/owner/repo/releases/download/v1.0.0/ghplugin.whl",
                "github_repo": "owner/repo",
            },
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            source = downloader.get_plugin_source("ghplugin")

        assert source is not None
        assert source.type == PluginSourceType.GITHUB_RELEASE
        assert source.github_repo == "owner/repo"

    def test_get_source_legacy_manifest(self, tmp_path: Path) -> None:
        """Test getting source for legacy manifest without source field."""
        plugin_dir = tmp_path / "legacyplugin"
        plugin_dir.mkdir()
        manifest = {
            "plugin_name": "legacyplugin",
            "version": "1.0.0",
            "wheel_filename": "legacyplugin-1.0.0.whl",
            "sha256": "abc123",
            # No source field
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            source = downloader.get_plugin_source("legacyplugin")

        assert source is not None
        assert source.type == PluginSourceType.GITGUARDIAN_API

    def test_get_source_not_installed(self, tmp_path: Path) -> None:
        """Test getting source for non-installed plugin."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            source = downloader.get_plugin_source("nonexistent")

        assert source is None


class TestPluginSourceTypes:
    """Tests for PluginSource and PluginSourceType."""

    def test_source_to_dict(self) -> None:
        """Test PluginSource serialization."""
        source = PluginSource(
            type=PluginSourceType.GITHUB_RELEASE,
            url="https://example.com",
            github_repo="owner/repo",
            sha256="abc123",
        )

        data = source.to_dict()

        assert data["type"] == "github_release"
        assert data["url"] == "https://example.com"
        assert data["github_repo"] == "owner/repo"
        assert data["sha256"] == "abc123"

    def test_source_from_dict(self) -> None:
        """Test PluginSource deserialization."""
        data = {
            "type": "local_file",
            "local_path": "/path/to/wheel.whl",
            "sha256": "def456",
        }

        source = PluginSource.from_dict(data)

        assert source.type == PluginSourceType.LOCAL_FILE
        assert source.local_path == "/path/to/wheel.whl"
        assert source.sha256 == "def456"

    def test_source_minimal(self) -> None:
        """Test PluginSource with minimal fields."""
        source = PluginSource(type=PluginSourceType.GITGUARDIAN_API)

        data = source.to_dict()

        assert data == {"type": "gitguardian_api"}


class TestDownloadFromUrlEdgeCases:
    """Additional tests for download_from_url edge cases."""

    def test_download_from_url_invalid_scheme(self, tmp_path: Path) -> None:
        """Test download fails with invalid URL scheme."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            downloader = PluginDownloader()

            with pytest.raises(DownloadError) as exc_info:
                downloader.download_from_url("ftp://example.com/plugin.whl")

            assert "Invalid URL scheme" in str(exc_info.value)

    def test_download_from_url_network_error(self, tmp_path: Path) -> None:
        """Test download from URL handles network errors."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch(
                "requests.get", side_effect=requests.RequestException("Network error")
            ):
                downloader = PluginDownloader()

                with pytest.raises(DownloadError) as exc_info:
                    downloader.download_from_url("https://example.com/plugin.whl")

                assert "Failed to download from URL" in str(exc_info.value)

    def test_download_from_url_invalid_wheel(self, tmp_path: Path) -> None:
        """Test download from URL with invalid wheel content."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        # Create invalid wheel content
        invalid_content = b"not a valid wheel"

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [invalid_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                downloader = PluginDownloader()

                with pytest.raises(DownloadError) as exc_info:
                    downloader.download_from_url("https://example.com/plugin.whl")

                assert "not a valid wheel" in str(exc_info.value)

    def test_download_from_url_no_whl_extension(self, tmp_path: Path) -> None:
        """Test download from URL defaults filename when not .whl."""
        # Create wheel content
        wheel_dir = tmp_path / "wheel_content"
        wheel_dir.mkdir()
        wheel_path = create_test_wheel(wheel_dir, "testplugin", "1.0.0")
        wheel_content = wheel_path.read_bytes()
        sha256 = hashlib.sha256(wheel_content).hexdigest()

        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [wheel_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                with patch(
                    "ggshield.core.plugin.downloader.verify_wheel_signature",
                    return_value=MOCK_SIG_INFO,
                ):
                    downloader = PluginDownloader()
                    plugin_name, version, _ = downloader.download_from_url(
                        "https://example.com/download?file=something",
                        sha256=sha256,
                    )

        assert plugin_name == "testplugin"
        assert version == "1.0.0"


class TestGitHubArtifactEdgeCases:
    """Additional tests for GitHub artifact download edge cases."""

    def test_github_artifact_success(self, tmp_path: Path) -> None:
        """Test successful GitHub artifact download."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        # Create a wheel for the artifact
        wheel_dir = tmp_path / "wheel_content"
        wheel_dir.mkdir()
        wheel_path = create_test_wheel(wheel_dir, "artifactplugin", "1.0.0")
        wheel_content = wheel_path.read_bytes()

        # Create artifact ZIP containing the wheel
        artifact_content = _create_artifact_zip(
            wheel_content, "artifactplugin-1.0.0.whl"
        )

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [artifact_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                with patch(
                    "ggshield.core.plugin.downloader.verify_wheel_signature",
                    return_value=MOCK_SIG_INFO,
                ):
                    with patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
                        downloader = PluginDownloader()
                        plugin_name, version, installed_path = (
                            downloader.download_from_github_artifact(
                                "https://github.com/owner/repo/actions/runs/123/artifacts/456"
                            )
                        )

        assert plugin_name == "artifactplugin"
        assert version == "1.0.0"
        assert installed_path.exists()

    def test_github_artifact_network_error(self, tmp_path: Path) -> None:
        """Test GitHub artifact download handles network errors."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch(
                "requests.get", side_effect=requests.RequestException("Network error")
            ):
                with patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
                    downloader = PluginDownloader()

                    with pytest.raises(GitHubArtifactError) as exc_info:
                        downloader.download_from_github_artifact(
                            "https://github.com/owner/repo/actions/runs/123/artifacts/456"
                        )

                    assert "Failed to download artifact" in str(exc_info.value)

    def test_github_artifact_no_wheel_in_zip(self, tmp_path: Path) -> None:
        """Test GitHub artifact fails when no wheel in ZIP."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        # Create artifact ZIP without wheel
        artifact_content = _create_artifact_zip(b"readme content", "README.md")

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [artifact_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                with patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
                    downloader = PluginDownloader()

                    with pytest.raises(GitHubArtifactError) as exc_info:
                        downloader.download_from_github_artifact(
                            "https://github.com/owner/repo/actions/runs/123/artifacts/456"
                        )

                    assert "No wheel file found" in str(exc_info.value)

    def test_github_artifact_gh_token_fallback(self, tmp_path: Path) -> None:
        """Test GitHub artifact uses gh CLI token as fallback."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch.dict("os.environ", {}, clear=True):
                with patch.object(
                    PluginDownloader, "_get_gh_token", return_value="gh-cli-token"
                ):
                    with patch(
                        "requests.get",
                        side_effect=requests.RequestException("Network error"),
                    ):
                        downloader = PluginDownloader()

                        with pytest.raises(GitHubArtifactError) as exc_info:
                            downloader.download_from_github_artifact(
                                "https://github.com/owner/repo/actions/runs/123/artifacts/456"
                            )

                        # Should have tried to download (token was available)
                        assert "Failed to download artifact" in str(exc_info.value)


class TestGetGhToken:
    """Tests for _get_gh_token helper."""

    def test_get_gh_token_success(self, tmp_path: Path) -> None:
        """Test _get_gh_token returns token from gh CLI."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "gh-token-123\n"

            with patch("subprocess.run", return_value=mock_result):
                token = downloader._get_gh_token()

            assert token == "gh-token-123"

    def test_get_gh_token_failure(self, tmp_path: Path) -> None:
        """Test _get_gh_token returns None when gh CLI fails."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

            mock_result = MagicMock()
            mock_result.returncode = 1

            with patch("subprocess.run", return_value=mock_result):
                token = downloader._get_gh_token()

            assert token is None

    def test_get_gh_token_not_installed(self, tmp_path: Path) -> None:
        """Test _get_gh_token returns None when gh CLI not installed."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

            with patch("subprocess.run", side_effect=FileNotFoundError()):
                token = downloader._get_gh_token()

            assert token is None


def _create_artifact_zip(content: bytes, filename: str) -> bytes:
    """Helper to create an artifact ZIP file in memory."""
    import io

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr(filename, content)
    return buffer.getvalue()
