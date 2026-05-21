"""
Tests for the plugin status command.
"""

from unittest import mock

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.core.plugin.client import PluginCatalog, PluginInfo


class TestPluginStatus:
    """Tests for 'ggshield plugin status' command."""

    def test_status_shows_available_plugins(self, cli_fs_runner):
        """
        GIVEN plugins are available in the catalog
        WHEN running 'ggshield plugin status'
        THEN it shows the 'Available Plugins' section without plan or features
        """
        mock_catalog = PluginCatalog(
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
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.status.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.status.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.status.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.status.PluginDownloader"
            ) as mock_downloader_class,
        ):
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config.is_plugin_enabled.return_value = False
            mock_config_class.load.return_value = mock_config

            mock_downloader = mock.MagicMock()
            mock_downloader.get_installed_version.return_value = None
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli, ["plugin", "status"], catch_exceptions=False
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Available Plugins" in result.output
        assert "Token Scanner" in result.output
        # No plan or features section
        assert "Account Status" not in result.output
        assert "Plan:" not in result.output
        assert "Features" not in result.output

    def test_status_plugins_not_enabled(self, cli_fs_runner):
        """
        GIVEN the platform has plugins disabled
        WHEN running 'ggshield plugin status'
        THEN it shows a clean error message
        """
        from ggshield.core.plugin.client import PluginsNotEnabledError

        with (
            mock.patch(
                "ggshield.cmd.plugin.status.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.status.PluginAPIClient"
            ) as mock_plugin_api_client_class,
        ):
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.side_effect = (
                PluginsNotEnabledError()
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "status"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "not available" in result.output.lower()
        assert "administrator" in result.output.lower()

    def test_status_shows_installed_plugins(self, cli_fs_runner):
        """
        GIVEN a plugin is installed
        WHEN running 'ggshield plugin status'
        THEN it shows the installed version
        """
        mock_catalog = PluginCatalog(
            plugins=[
                PluginInfo(
                    name="tokenscanner",
                    display_name="Token Scanner",
                    description="Local secret scanning",
                    available=True,
                    latest_version="1.1.0",
                    reason=None,
                ),
            ],
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.status.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.status.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.status.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.status.PluginDownloader"
            ) as mock_downloader_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config.is_plugin_enabled.return_value = True
            mock_config_class.load.return_value = mock_config

            mock_downloader = mock.MagicMock()
            mock_downloader.get_installed_version.return_value = "1.0.0"
            mock_downloader.get_installed_signature_label.return_value = None
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli, ["plugin", "status"], catch_exceptions=False
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "installed v1.0.0" in result.output
        assert "update available: v1.1.0" in result.output

    def test_status_shows_signature_label_for_installed_plugin(self, cli_fs_runner):
        """
        GIVEN an installed plugin with persisted trust metadata
        WHEN running 'ggshield plugin status'
        THEN it shows the human-readable signature label.
        """
        mock_catalog = PluginCatalog(
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
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.status.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.status.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.status.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.status.PluginDownloader"
            ) as mock_downloader_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config.is_plugin_enabled.return_value = True
            mock_config_class.load.return_value = mock_config

            mock_downloader = mock.MagicMock()
            mock_downloader.get_installed_version.return_value = "1.0.0"
            mock_downloader.get_installed_signature_label.return_value = (
                "unsigned (trusted)"
            )
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli, ["plugin", "status"], catch_exceptions=False
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Signature: unsigned (trusted)" in result.output

    def test_status_api_error(self, cli_fs_runner):
        """
        GIVEN fetching plugins fails
        WHEN running 'ggshield plugin status'
        THEN it shows an error
        """
        from ggshield.core.plugin.client import PluginAPIError

        with (
            mock.patch(
                "ggshield.cmd.plugin.status.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.status.PluginAPIClient"
            ) as mock_plugin_api_client_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.side_effect = PluginAPIError(
                "API key invalid"
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "status"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "API key invalid" in result.output

    def test_status_connection_error(self, cli_fs_runner):
        """
        GIVEN connection to GitGuardian fails
        WHEN running 'ggshield plugin status'
        THEN it shows an error
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.status.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.status.PluginAPIClient"
            ) as mock_plugin_api_client_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.side_effect = Exception(
                "Connection refused"
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "status"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to fetch plugin catalog" in result.output

    def test_status_shows_installed_but_disabled(self, cli_fs_runner):
        """
        GIVEN a plugin is installed but disabled
        WHEN running 'ggshield plugin status'
        THEN it shows the plugin as disabled
        """
        mock_catalog = PluginCatalog(
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
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.status.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.status.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.status.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.status.PluginDownloader"
            ) as mock_downloader_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config.is_plugin_enabled.return_value = False
            mock_config_class.load.return_value = mock_config

            mock_downloader = mock.MagicMock()
            mock_downloader.get_installed_version.return_value = "1.0.0"
            mock_downloader.get_installed_signature_label.return_value = None
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli, ["plugin", "status"], catch_exceptions=False
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "installed v1.0.0" in result.output
        assert "disabled" in result.output

    def test_status_shows_unavailable_plugin_without_reason(self, cli_fs_runner):
        """
        GIVEN a plugin is not available without a specific reason
        WHEN running 'ggshield plugin status'
        THEN it shows the plugin as not available
        """
        mock_catalog = PluginCatalog(
            plugins=[
                PluginInfo(
                    name="premium",
                    display_name="Premium Plugin",
                    description="Premium features",
                    available=False,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.status.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.status.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.status.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch(
                "ggshield.cmd.plugin.status.PluginDownloader"
            ) as mock_downloader_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config.is_plugin_enabled.return_value = False
            mock_config_class.load.return_value = mock_config

            mock_downloader = mock.MagicMock()
            mock_downloader.get_installed_version.return_value = None
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli, ["plugin", "status"], catch_exceptions=False
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "not available" in result.output
        # Should not show "Reason:" when reason is None
        assert "Reason:" not in result.output
