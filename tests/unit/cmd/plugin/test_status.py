"""
Tests for the plugin status command.
"""

from unittest import mock

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.core.plugin.client import PluginCatalog, PluginInfo


class TestPluginStatus:
    """Tests for 'ggshield plugin status' command."""

    def test_status_shows_plan(self, cli_fs_runner):
        """
        GIVEN a user with an account
        WHEN running 'ggshield plugin status'
        THEN it shows the plan information
        """
        mock_catalog = PluginCatalog(
            plan="Enterprise",
            plugins=[],
            features={},
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
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config.is_plugin_enabled.return_value = False
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli, ["plugin", "status"], catch_exceptions=False
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Account Status" in result.output
        assert "Plan: Enterprise" in result.output

    def test_status_shows_features(self, cli_fs_runner):
        """
        GIVEN a user with features enabled
        WHEN running 'ggshield plugin status'
        THEN it shows the features
        """
        mock_catalog = PluginCatalog(
            plan="Business",
            plugins=[],
            features={
                "local_scanning": True,
                "advanced_detection": False,
            },
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
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config.is_plugin_enabled.return_value = False
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli, ["plugin", "status"], catch_exceptions=False
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Features" in result.output
        assert "local_scanning" in result.output
        assert "enabled" in result.output
        assert "advanced_detection" in result.output
        assert "disabled" in result.output

    def test_status_shows_available_plugins(self, cli_fs_runner):
        """
        GIVEN plugins are available
        WHEN running 'ggshield plugin status'
        THEN it shows the available plugins
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
                PluginInfo(
                    name="premium",
                    display_name="Premium Plugin",
                    description="Premium features",
                    available=False,
                    latest_version="2.0.0",
                    reason="Requires Enterprise Plus plan",
                ),
            ],
            features={},
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
        assert "Available Plugins" in result.output
        assert "Token Scanner" in result.output
        assert "tokenscanner" in result.output
        assert "Local secret scanning" in result.output
        assert "Premium Plugin" in result.output
        assert "not available" in result.output
        assert "Requires Enterprise Plus plan" in result.output

    def test_status_shows_installed_plugins(self, cli_fs_runner):
        """
        GIVEN a plugin is installed
        WHEN running 'ggshield plugin status'
        THEN it shows the installed version
        """
        mock_catalog = PluginCatalog(
            plan="Enterprise",
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
            features={},
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
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli, ["plugin", "status"], catch_exceptions=False
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "installed v1.0.0" in result.output
        assert "update available: v1.1.0" in result.output

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
            plan="Free",
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
            features={},
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
