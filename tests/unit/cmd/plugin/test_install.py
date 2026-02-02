"""
Tests for the enterprise install command.
"""

from unittest import mock

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.core.plugin.client import PluginCatalog, PluginDownloadInfo, PluginInfo


class TestPluginInstall:
    """Tests for 'ggshield plugin install' command."""

    def test_install_requires_plugin_name(self, cli_fs_runner):
        """
        GIVEN no plugin name
        WHEN running 'ggshield plugin install'
        THEN it shows a usage error
        """
        result = cli_fs_runner.invoke(cli, ["plugin", "install"])

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "PLUGIN_NAME" in result.output

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
        mock_downloader.download_and_install.assert_called_once_with(
            mock_download_info, "tokenscanner"
        )
        mock_config.enable_plugin.assert_called_once_with(
            "tokenscanner", version="1.0.0"
        )
        mock_config.save.assert_called_once()

    def test_install_unavailable_plugin(self, cli_fs_runner):
        """
        GIVEN a plugin exists but is not available
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error with reason
        """
        mock_catalog = PluginCatalog(
            plan="Free",
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=False,
                    latest_version="1.0.0",
                    reason="Requires Business plan",
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
        assert "Requires Business plan" in result.output

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
        from ggshield.core.plugin.downloader import DownloadError

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

    def test_install_unavailable_plugin_without_reason(self, cli_fs_runner):
        """
        GIVEN a plugin exists but is not available (without reason)
        WHEN running 'ggshield plugin install <plugin>'
        THEN it shows an error without reason
        """
        mock_catalog = PluginCatalog(
            plan="Free",
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=False,
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
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "install", "tokenscanner"])

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "not available" in result.output
        # Should not show "Reason:" when reason is None
        assert "Reason:" not in result.output
