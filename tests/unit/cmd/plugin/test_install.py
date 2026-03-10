"""
Tests for the enterprise install command.
"""

from pathlib import Path
from unittest import mock

import pytest

from ggshield.__main__ import cli
from ggshield.cmd.plugin.install import detect_source_type
from ggshield.core.errors import ExitCode
from ggshield.core.plugin.client import (
    PluginCatalog,
    PluginDownloadInfo,
    PluginInfo,
    PluginSourceType,
)
from ggshield.core.plugin.downloader import ChecksumMismatchError, DownloadError
from ggshield.core.plugin.signature import SignatureStatus, SignatureVerificationError


class TestPluginInstall:
    """Tests for 'ggshield plugin install' command."""

    def test_install_requires_plugin_source(self, cli_fs_runner):
        """
        GIVEN no plugin source
        WHEN running 'ggshield plugin install'
        THEN it shows a usage error
        """
        result = cli_fs_runner.invoke(cli, ["plugin", "install"])

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "PLUGIN_SOURCE" in result.output

    def test_install_single_plugin(self, cli_fs_runner):
        """
        GIVEN a plugin is available
        WHEN running 'ggshield plugin install <plugin>'
        THEN the plugin is downloaded and installed
        """
        mock_catalog = PluginCatalog(
            plan="Enterprise",
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=True,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
            features={},
        )

        mock_download_info = PluginDownloadInfo(
            download_url="https://example.com/plugin.whl",
            filename="tokenscanner-1.0.0.whl",
            sha256="abc123",
            version="1.0.0",
            expires_at="2099-12-31T23:59:59Z",
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.get_download_info.return_value = mock_download_info
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_downloader = mock.MagicMock()
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", "tokenscanner"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installing tokenscanner" in result.output
        assert "Installed tokenscanner v1.0.0" in result.output
        mock_downloader.download_and_install.assert_called_once()
        call_args = mock_downloader.download_and_install.call_args
        assert call_args[0] == (mock_download_info, "tokenscanner")
        mock_config.enable_plugin.assert_called_once_with(
            "tokenscanner", version="1.0.0"
        )
        mock_config.save.assert_called_once()

    @pytest.mark.parametrize(
        "reason",
        [
            pytest.param("Requires Business plan", id="with_reason"),
            pytest.param(None, id="without_reason"),
        ],
    )
    def test_install_unavailable_plugin(self, cli_fs_runner, reason):
        mock_catalog = PluginCatalog(
            plan="Free",
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=False,
                    latest_version="1.0.0",
                    reason=reason,
                ),
            ],
            features={},
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "not available" in result.output
        if reason:
            assert reason in result.output
        else:
            assert "Reason:" not in result.output

    def test_install_unknown_plugin(self, cli_fs_runner):
        """
        GIVEN a plugin does not exist
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error
        """
        mock_catalog = PluginCatalog(
            plan="Enterprise",
            plugins=[],
            features={},
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "nonexistent"])

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "Unknown plugin" in result.output
        assert "ggshield plugin status" in result.output

    def test_install_with_version(self, cli_fs_runner):
        """
        GIVEN a plugin is available
        WHEN running 'ggshield plugin install <plugin> --version X.Y.Z'
        THEN the specified version is requested
        """
        mock_catalog = PluginCatalog(
            plan="Enterprise",
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=True,
                    latest_version="2.0.0",
                    reason=None,
                ),
            ],
            features={},
        )

        mock_download_info = PluginDownloadInfo(
            download_url="https://example.com/plugin.whl",
            filename="plugin-1.0.0.whl",
            sha256="abc123",
            version="1.0.0",
            expires_at="2099-12-31T23:59:59Z",
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.get_download_info.return_value = mock_download_info
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_downloader = mock.MagicMock()
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", "tokenscanner", "--version", "1.5.0"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        mock_plugin_api_client.get_download_info.assert_called_once_with(
            "tokenscanner", version="1.5.0"
        )

    def test_install_download_error(self, cli_fs_runner):
        """
        GIVEN downloading a plugin fails
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error
        """
        mock_catalog = PluginCatalog(
            plan="Enterprise",
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=True,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
            features={},
        )

        mock_download_info = PluginDownloadInfo(
            download_url="https://example.com/plugin.whl",
            filename="tokenscanner-1.0.0.whl",
            sha256="abc123",
            version="1.0.0",
            expires_at="2099-12-31T23:59:59Z",
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.get_download_info.return_value = mock_download_info
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_downloader = mock.MagicMock()
            mock_downloader.download_and_install.side_effect = DownloadError(
                "Network error"
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to install tokenscanner" in result.output
        assert "Network error" in result.output

    def test_install_api_error(self, cli_fs_runner):
        """
        GIVEN the API returns an error
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error
        """
        from ggshield.core.plugin.client import PluginAPIError

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.side_effect = PluginAPIError(
                "API error"
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "API error" in result.output

    def test_install_connection_error(self, cli_fs_runner):
        """
        GIVEN connection to GitGuardian fails
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.side_effect = Exception(
                "Connection refused"
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to connect to GitGuardian" in result.output

    def test_install_plugin_not_available_error(self, cli_fs_runner):
        """
        GIVEN getting download info fails with PluginNotAvailableError
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error
        """
        from ggshield.core.plugin.client import PluginNotAvailableError

        mock_catalog = PluginCatalog(
            plan="Enterprise",
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=True,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
            features={},
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.get_download_info.side_effect = (
                PluginNotAvailableError("tokenscanner", "Version not found")
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_downloader = mock.MagicMock()
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to install tokenscanner" in result.output

    def test_install_generic_error(self, cli_fs_runner):
        """
        GIVEN an unexpected error occurs during install
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error
        """
        mock_catalog = PluginCatalog(
            plan="Enterprise",
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=True,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
            features={},
        )

        mock_download_info = PluginDownloadInfo(
            download_url="https://example.com/plugin.whl",
            filename="tokenscanner-1.0.0.whl",
            sha256="abc123",
            version="1.0.0",
            expires_at="2099-12-31T23:59:59Z",
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.get_download_info.return_value = mock_download_info
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_downloader = mock.MagicMock()
            mock_downloader.download_and_install.side_effect = Exception(
                "Unexpected error"
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to install tokenscanner" in result.output


class TestDetectSourceType:
    """Tests for detect_source_type function."""

    def test_detect_github_artifact(self) -> None:
        """Test detection of GitHub artifact URLs."""
        url = "https://github.com/owner/repo/actions/runs/123456/artifacts/789"
        assert detect_source_type(url) == PluginSourceType.GITHUB_ARTIFACT

    def test_detect_github_release(self) -> None:
        """Test detection of GitHub release URLs."""
        url = "https://github.com/owner/repo/releases/download/v1.0.0/plugin.whl"
        assert detect_source_type(url) == PluginSourceType.GITHUB_RELEASE

    def test_detect_generic_url(self) -> None:
        """Test detection of generic HTTPS URLs."""
        assert (
            detect_source_type("https://example.com/plugin.whl") == PluginSourceType.URL
        )
        assert (
            detect_source_type("https://pypi.org/packages/plugin.whl")
            == PluginSourceType.URL
        )

    def test_detect_http_url(self) -> None:
        """Test detection of HTTP URLs (will be rejected later)."""
        assert (
            detect_source_type("http://example.com/plugin.whl") == PluginSourceType.URL
        )

    def test_detect_local_file(self, tmp_path: Path) -> None:
        """Test detection of local wheel files."""
        wheel_path = tmp_path / "plugin.whl"
        wheel_path.touch()
        assert detect_source_type(str(wheel_path)) == PluginSourceType.LOCAL_FILE

    def test_detect_local_file_nonexistent(self) -> None:
        """Test non-existent local wheel paths are treated as local sources."""
        assert detect_source_type("./nonexistent.whl") == PluginSourceType.LOCAL_FILE

    def test_detect_plugin_name(self) -> None:
        """Test plugin names default to GitGuardian API."""
        assert detect_source_type("tokenscanner") == PluginSourceType.GITGUARDIAN_API
        assert detect_source_type("my-plugin") == PluginSourceType.GITGUARDIAN_API


class TestInstallFromLocalWheel:
    """Tests for installing from local wheel files."""

    def test_install_local_wheel_success(self, cli_fs_runner, tmp_path: Path) -> None:
        """
        GIVEN a valid local wheel file
        WHEN running 'ggshield plugin install <path>'
        THEN the plugin is installed from the wheel
        """
        wheel_path = tmp_path / "myplugin-1.0.0.whl"
        wheel_path.touch()

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.LOCAL_FILE,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.install_from_wheel.return_value = (
                "myplugin",
                "1.0.0",
                wheel_path,
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", str(wheel_path)],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installed myplugin v1.0.0" in result.output
        mock_downloader.install_from_wheel.assert_called_once()
        mock_config.enable_plugin.assert_called_once_with("myplugin", version="1.0.0")


class TestInstallFromUrl:
    """Tests for installing from URLs."""

    def test_install_url_with_sha256(self, cli_fs_runner) -> None:
        """
        GIVEN a URL with SHA256 checksum
        WHEN running 'ggshield plugin install <url> --sha256 <hash>'
        THEN the plugin is downloaded and verified
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.URL,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_url.return_value = (
                "urlplugin",
                "2.0.0",
                Path("/fake/path.whl"),
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://example.com/plugin.whl",
                    "--sha256",
                    "abc123",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installed urlplugin v2.0.0" in result.output
        mock_downloader.download_from_url.assert_called_once()
        call_args = mock_downloader.download_from_url.call_args
        assert call_args[0] == ("https://example.com/plugin.whl", "abc123")

    def test_install_http_url_rejected(self, cli_fs_runner) -> None:
        """
        GIVEN an HTTP URL (not HTTPS)
        WHEN running 'ggshield plugin install <url>'
        THEN the install fails with security error
        """
        from ggshield.core.plugin.downloader import InsecureSourceError

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.URL,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_url.side_effect = InsecureSourceError(
                "HTTP URLs are not allowed"
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", "http://example.com/plugin.whl"],
            )

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "HTTP URLs are not allowed" in result.output


class TestInstallFromGitHubRelease:
    """Tests for installing from GitHub releases."""

    def test_install_github_release(self, cli_fs_runner) -> None:
        """
        GIVEN a GitHub release URL
        WHEN running 'ggshield plugin install <url>'
        THEN the plugin is installed from the release
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.GITHUB_RELEASE,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_github_release.return_value = (
                "ghplugin",
                "1.5.0",
                Path("/fake/path.whl"),
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/releases/download/v1.5.0/plugin.whl",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installed ghplugin v1.5.0" in result.output


class TestInstallFromGitHubArtifact:
    """Tests for installing from GitHub Actions artifacts."""

    def test_install_github_artifact(self, cli_fs_runner) -> None:
        """
        GIVEN a GitHub artifact URL
        WHEN running 'ggshield plugin install <url>'
        THEN the plugin is installed from the artifact
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.GITHUB_ARTIFACT,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_github_artifact.return_value = (
                "artifactplugin",
                "0.1.0",
                Path("/fake/path.whl"),
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/actions/runs/123/artifacts/456",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installed artifactplugin v0.1.0" in result.output

    def test_install_github_artifact_warning(self, cli_fs_runner) -> None:
        """
        GIVEN a GitHub artifact URL
        WHEN running 'ggshield plugin install <url>'
        THEN a warning about ephemeral artifacts is displayed
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.GITHUB_ARTIFACT,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_github_artifact.return_value = (
                "artifactplugin",
                "0.1.0",
                Path("/fake/path.whl"),
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/actions/runs/123/artifacts/456",
                ],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "ephemeral" in result.output.lower()

    def test_install_github_artifact_auth_error(self, cli_fs_runner) -> None:
        """
        GIVEN a GitHub artifact URL with missing authentication
        WHEN running 'ggshield plugin install <url>'
        THEN an authentication error is displayed
        """
        from ggshield.core.plugin.downloader import GitHubArtifactError

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.GITHUB_ARTIFACT,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.download_from_github_artifact.side_effect = (
                GitHubArtifactError("GitHub authentication required")
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/actions/runs/123/artifacts/456",
                ],
            )

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "GitHub authentication required" in result.output


class TestInstallErrorHandling:
    """Tests for error handling in various install scenarios."""

    def test_install_local_wheel_not_found(self, cli_fs_runner, tmp_path: Path) -> None:
        wheel_path = tmp_path / "nonexistent.whl"

        with mock.patch(
            "ggshield.cmd.plugin.install.detect_source_type",
            return_value=PluginSourceType.LOCAL_FILE,
        ):
            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", str(wheel_path)],
            )

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "Wheel file not found" in result.output

    @pytest.mark.parametrize(
        "error",
        [
            pytest.param(DownloadError("Invalid wheel"), id="download_error"),
            pytest.param(Exception("Unexpected"), id="generic_error"),
        ],
    )
    def test_install_local_wheel_error(
        self, cli_fs_runner, tmp_path: Path, error: Exception
    ) -> None:
        wheel_path = tmp_path / "broken.whl"
        wheel_path.touch()

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch("ggshield.cmd.plugin.install.EnterpriseConfig"),
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.LOCAL_FILE,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.install_from_wheel.side_effect = error
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", str(wheel_path)],
            )

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to install from wheel" in result.output

    @pytest.mark.parametrize(
        "source_type, method, cli_args, error, expected_msg",
        [
            pytest.param(
                PluginSourceType.URL,
                "download_from_url",
                ["plugin", "install", "https://example.com/plugin.whl"],
                DownloadError("Network error"),
                "Failed to install from URL",
                id="url-download_error",
            ),
            pytest.param(
                PluginSourceType.URL,
                "download_from_url",
                ["plugin", "install", "https://example.com/plugin.whl"],
                Exception("Unexpected"),
                "Failed to install from URL",
                id="url-generic_error",
            ),
            pytest.param(
                PluginSourceType.GITHUB_RELEASE,
                "download_from_github_release",
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/releases/download/v1/p.whl",
                ],
                DownloadError("Not found"),
                "Failed to install from GitHub release",
                id="github_release-download_error",
            ),
            pytest.param(
                PluginSourceType.GITHUB_RELEASE,
                "download_from_github_release",
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/releases/download/v1/p.whl",
                ],
                Exception("Unexpected"),
                "Failed to install from GitHub release",
                id="github_release-generic_error",
            ),
            pytest.param(
                PluginSourceType.GITHUB_ARTIFACT,
                "download_from_github_artifact",
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/actions/runs/123/artifacts/456",
                ],
                DownloadError("Failed to extract"),
                "Failed to install from GitHub artifact",
                id="github_artifact-download_error",
            ),
            pytest.param(
                PluginSourceType.GITHUB_ARTIFACT,
                "download_from_github_artifact",
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/actions/runs/123/artifacts/456",
                ],
                Exception("Unexpected"),
                "Failed to install from GitHub artifact",
                id="github_artifact-generic_error",
            ),
        ],
    )
    def test_install_error(
        self, cli_fs_runner, source_type, method, cli_args, error, expected_msg
    ) -> None:
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch("ggshield.cmd.plugin.install.EnterpriseConfig"),
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=source_type,
            ),
        ):
            mock_downloader = mock.MagicMock()
            getattr(mock_downloader, method).side_effect = error
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(cli, cli_args)

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert expected_msg in result.output

    @pytest.mark.parametrize(
        "source_type, method, cli_args",
        [
            pytest.param(
                PluginSourceType.URL,
                "download_from_url",
                [
                    "plugin",
                    "install",
                    "https://example.com/plugin.whl",
                    "--sha256",
                    "wrong",
                ],
                id="url",
            ),
            pytest.param(
                PluginSourceType.GITHUB_RELEASE,
                "download_from_github_release",
                [
                    "plugin",
                    "install",
                    "https://github.com/owner/repo/releases/download/v1/p.whl",
                    "--sha256",
                    "wrong",
                ],
                id="github_release",
            ),
        ],
    )
    def test_install_checksum_mismatch(
        self, cli_fs_runner, source_type, method, cli_args
    ) -> None:
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch("ggshield.cmd.plugin.install.EnterpriseConfig"),
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=source_type,
            ),
        ):
            mock_downloader = mock.MagicMock()
            getattr(mock_downloader, method).side_effect = ChecksumMismatchError(
                "expected123", "actual456"
            )
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(cli, cli_args)

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Checksum verification failed" in result.output


class TestSignatureVerificationHandling:
    """Tests for signature verification error handling in install commands."""

    def test_gitguardian_install_signature_error(self, cli_fs_runner) -> None:
        """
        GIVEN a plugin with invalid signature
        WHEN installing from GitGuardian API
        THEN signature error is shown with --allow-unsigned hint
        """
        mock_catalog = PluginCatalog(
            plan="Enterprise",
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=True,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
            features={},
        )

        mock_download_info = PluginDownloadInfo(
            download_url="https://example.com/plugin.whl",
            filename="tokenscanner-1.0.0.whl",
            sha256="abc123",
            version="1.0.0",
            expires_at="2099-12-31T23:59:59Z",
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.get_download_info.return_value = mock_download_info
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_downloader = mock.MagicMock()
            mock_downloader.download_and_install.side_effect = (
                SignatureVerificationError(
                    SignatureStatus.INVALID, "no trusted identity matched"
                )
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config.get_signature_mode.return_value = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Signature verification failed" in result.output
        assert "--allow-unsigned" in result.output

    def test_local_wheel_signature_error(self, cli_fs_runner, tmp_path: Path) -> None:
        """
        GIVEN a local wheel with invalid signature
        WHEN installing from local wheel
        THEN signature error is shown with --allow-unsigned hint
        """
        wheel_path = tmp_path / "plugin.whl"
        wheel_path.touch()

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.LOCAL_FILE,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.install_from_wheel.side_effect = SignatureVerificationError(
                SignatureStatus.MISSING, "No bundle found"
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config.get_signature_mode.return_value = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(cli, ["plugin", "install", str(wheel_path)])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Signature verification failed" in result.output
        assert "--allow-unsigned" in result.output

    @pytest.mark.parametrize(
        "source_type, method, cli_args",
        [
            pytest.param(
                PluginSourceType.URL,
                "download_from_url",
                ["plugin", "install", "https://example.com/plugin.whl"],
                id="url",
            ),
            pytest.param(
                PluginSourceType.GITHUB_RELEASE,
                "download_from_github_release",
                [
                    "plugin",
                    "install",
                    "https://github.com/o/r/releases/download/v1/p.whl",
                ],
                id="github_release",
            ),
            pytest.param(
                PluginSourceType.GITHUB_ARTIFACT,
                "download_from_github_artifact",
                [
                    "plugin",
                    "install",
                    "https://github.com/o/r/actions/runs/1/artifacts/2",
                ],
                id="github_artifact",
            ),
        ],
    )
    def test_signature_error_all_sources(
        self, cli_fs_runner, source_type, method, cli_args
    ) -> None:
        """Test that SignatureVerificationError is handled for all source types."""
        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=source_type,
            ),
        ):
            mock_downloader = mock.MagicMock()
            getattr(mock_downloader, method).side_effect = SignatureVerificationError(
                SignatureStatus.INVALID, "bad signature"
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config.get_signature_mode.return_value = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(cli, cli_args)

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Signature verification failed" in result.output
        assert "--allow-unsigned" in result.output

    def test_allow_unsigned_flag(self, cli_fs_runner, tmp_path: Path) -> None:
        """
        GIVEN --allow-unsigned flag
        WHEN installing a plugin
        THEN signature mode is set to WARN (not STRICT)
        """
        wheel_path = tmp_path / "plugin.whl"
        wheel_path.touch()

        with (
            mock.patch(
                "ggshield.cmd.plugin.install.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.install.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.install.detect_source_type",
                return_value=PluginSourceType.LOCAL_FILE,
            ),
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.install_from_wheel.return_value = (
                "plugin",
                "1.0.0",
                wheel_path,
            )
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config.get_signature_mode.return_value = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "install", str(wheel_path), "--allow-unsigned"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        call_kwargs = mock_downloader.install_from_wheel.call_args[1]
        from ggshield.core.plugin.signature import SignatureVerificationMode

        assert call_kwargs["signature_mode"] == SignatureVerificationMode.WARN
