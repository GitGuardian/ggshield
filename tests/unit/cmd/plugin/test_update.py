"""
Tests for the enterprise update command.
"""

from pathlib import Path
from unittest import mock

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.core.plugin.client import PluginCatalog, PluginDownloadInfo, PluginInfo
from ggshield.core.plugin.loader import DiscoveredPlugin


class TestPluginUpdate:
    """Tests for 'ggshield plugin update' command."""

    def test_update_requires_plugin_or_all_or_check(self, cli_fs_runner):
        """
        GIVEN no plugin name or flags
        WHEN running 'ggshield plugin update'
        THEN it shows an error
        """
        result = cli_fs_runner.invoke(cli, ["plugin", "update"])

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "Please specify a plugin name" in result.output

    def test_update_check_shows_available_updates(self, cli_fs_runner):
        """
        GIVEN an outdated plugin is installed
        WHEN running 'ggshield plugin update --check'
        THEN it shows the available update
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

        mock_discovered_plugins = [
            DiscoveredPlugin(
                name="tokenscanner",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
        ]

        with (
            mock.patch(
                "ggshield.cmd.plugin.update.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.update.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch("ggshield.cmd.plugin.update.PluginLoader") as mock_loader_class,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginDownloader"
            ) as mock_downloader_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered_plugins
            mock_loader_class.return_value = mock_loader

            mock_downloader = mock.MagicMock()
            mock_downloader.get_plugin_source.return_value = None
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "update", "--check"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Updates Available" in result.output
        assert "tokenscanner" in result.output
        assert "1.0.0 -> 2.0.0" in result.output

    def test_update_check_all_up_to_date(self, cli_fs_runner):
        """
        GIVEN all plugins are up to date
        WHEN running 'ggshield plugin update --check'
        THEN it shows everything is up to date
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

        mock_discovered_plugins = [
            DiscoveredPlugin(
                name="tokenscanner",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
        ]

        with (
            mock.patch(
                "ggshield.cmd.plugin.update.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.update.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch("ggshield.cmd.plugin.update.PluginLoader") as mock_loader_class,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginDownloader"
            ) as mock_downloader_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered_plugins
            mock_loader_class.return_value = mock_loader

            mock_downloader = mock.MagicMock()
            mock_downloader.get_plugin_source.return_value = None
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "update", "--check"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "up to date" in result.output

    def test_update_single_plugin(self, cli_fs_runner):
        """
        GIVEN an outdated plugin
        WHEN running 'ggshield plugin update <plugin>'
        THEN the plugin is updated
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

        mock_discovered_plugins = [
            DiscoveredPlugin(
                name="tokenscanner",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
        ]

        mock_download_info = PluginDownloadInfo(
            download_url="https://example.com/plugin.whl",
            filename="tokenscanner-2.0.0.whl",
            sha256="abc123",
            version="2.0.0",
            expires_at="2099-12-31T23:59:59Z",
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.update.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.update.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch("ggshield.cmd.plugin.update.PluginLoader") as mock_loader_class,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginDownloader"
            ) as mock_downloader_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.get_download_info.return_value = mock_download_info
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered_plugins
            mock_loader_class.return_value = mock_loader

            mock_downloader = mock.MagicMock()
            # Return None for get_plugin_source to treat as legacy GitGuardian plugin
            mock_downloader.get_plugin_source.return_value = None
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "update", "tokenscanner"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Updating tokenscanner" in result.output
        assert "1.0.0 -> 2.0.0" in result.output
        assert "Updated tokenscanner to v2.0.0" in result.output
        mock_downloader.download_and_install.assert_called_once()
        mock_config.save.assert_called_once()

    def test_update_not_installed(self, cli_fs_runner):
        """
        GIVEN a plugin is not installed
        WHEN running 'ggshield plugin update <plugin>'
        THEN it shows an error
        """
        mock_catalog = PluginCatalog(
            plan="Enterprise",
            plugins=[],
            features={},
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.update.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.update.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch("ggshield.cmd.plugin.update.PluginLoader") as mock_loader_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = []
            mock_loader_class.return_value = mock_loader

            result = cli_fs_runner.invoke(cli, ["plugin", "update", "notinstalled"])

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "not installed" in result.output

    def test_update_all(self, cli_fs_runner):
        """
        GIVEN multiple outdated plugins
        WHEN running 'ggshield plugin update --all'
        THEN all plugins are updated
        """
        mock_catalog = PluginCatalog(
            plan="Enterprise",
            plugins=[
                PluginInfo(
                    name="plugin1",
                    display_name="Plugin 1",
                    description="First plugin",
                    available=True,
                    latest_version="2.0.0",
                    reason=None,
                ),
                PluginInfo(
                    name="plugin2",
                    display_name="Plugin 2",
                    description="Second plugin",
                    available=True,
                    latest_version="3.0.0",
                    reason=None,
                ),
            ],
            features={},
        )

        mock_discovered_plugins = [
            DiscoveredPlugin(
                name="plugin1",
                entry_point=None,
                wheel_path=Path("/path/to/plugin1"),
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
            DiscoveredPlugin(
                name="plugin2",
                entry_point=None,
                wheel_path=Path("/path/to/plugin2"),
                is_installed=True,
                is_enabled=True,
                version="2.0.0",
            ),
        ]

        mock_download_info_1 = PluginDownloadInfo(
            download_url="https://example.com/plugin1.whl",
            filename="plugin1-2.0.0.whl",
            sha256="abc123",
            version="2.0.0",
            expires_at="2099-12-31T23:59:59Z",
        )
        mock_download_info_2 = PluginDownloadInfo(
            download_url="https://example.com/plugin2.whl",
            filename="plugin2-3.0.0.whl",
            sha256="def456",
            version="3.0.0",
            expires_at="2099-12-31T23:59:59Z",
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.update.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.update.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch("ggshield.cmd.plugin.update.PluginLoader") as mock_loader_class,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginDownloader"
            ) as mock_downloader_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.get_download_info.side_effect = [
                mock_download_info_1,
                mock_download_info_2,
            ]
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered_plugins
            mock_loader_class.return_value = mock_loader

            mock_downloader = mock.MagicMock()
            # Return None for get_plugin_source to treat as legacy GitGuardian plugin
            mock_downloader.get_plugin_source.return_value = None
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "update", "--all"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Updating plugin1" in result.output
        assert "Updating plugin2" in result.output
        assert "2 plugins updated successfully" in result.output
        assert mock_downloader.download_and_install.call_count == 2

    def test_update_api_error(self, cli_fs_runner):
        """
        GIVEN the API returns an error
        WHEN running 'ggshield plugin update --check'
        THEN it shows an error
        """
        from ggshield.core.plugin.client import PluginAPIError

        with (
            mock.patch(
                "ggshield.cmd.plugin.update.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginAPIClient"
            ) as mock_plugin_api_client_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.side_effect = PluginAPIError(
                "API error"
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "update", "--check"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "API error" in result.output

    def test_update_connection_error(self, cli_fs_runner):
        """
        GIVEN connection to GitGuardian fails
        WHEN running 'ggshield plugin update --check'
        THEN it shows an error
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.update.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginAPIClient"
            ) as mock_plugin_api_client_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.side_effect = Exception(
                "Connection refused"
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            result = cli_fs_runner.invoke(cli, ["plugin", "update", "--check"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to connect to GitGuardian" in result.output

    def test_update_no_plugins_installed(self, cli_fs_runner):
        """
        GIVEN no plugins are installed
        WHEN running 'ggshield plugin update --all'
        THEN it shows a message about no plugins
        """
        mock_catalog = PluginCatalog(
            plan="Enterprise",
            plugins=[],
            features={},
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.update.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.update.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch("ggshield.cmd.plugin.update.PluginLoader") as mock_loader_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = []
            mock_loader_class.return_value = mock_loader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "update", "--all"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "No plugins installed" in result.output

    def test_update_single_already_up_to_date(self, cli_fs_runner):
        """
        GIVEN a plugin is already up to date
        WHEN running 'ggshield plugin update <plugin>'
        THEN it shows the plugin is up to date
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

        mock_discovered_plugins = [
            DiscoveredPlugin(
                name="tokenscanner",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
        ]

        with (
            mock.patch(
                "ggshield.cmd.plugin.update.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.update.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch("ggshield.cmd.plugin.update.PluginLoader") as mock_loader_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered_plugins
            mock_loader_class.return_value = mock_loader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "update", "tokenscanner"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "tokenscanner" in result.output
        assert "up to date" in result.output

    def test_update_download_error(self, cli_fs_runner):
        """
        GIVEN downloading a plugin update fails
        WHEN running 'ggshield plugin update <plugin>'
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
                    latest_version="2.0.0",
                    reason=None,
                ),
            ],
            features={},
        )

        mock_discovered_plugins = [
            DiscoveredPlugin(
                name="tokenscanner",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
        ]

        mock_download_info = PluginDownloadInfo(
            download_url="https://example.com/plugin.whl",
            filename="tokenscanner-2.0.0.whl",
            sha256="abc123",
            version="2.0.0",
            expires_at="2099-12-31T23:59:59Z",
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.update.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.update.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch("ggshield.cmd.plugin.update.PluginLoader") as mock_loader_class,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginDownloader"
            ) as mock_downloader_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.get_download_info.return_value = mock_download_info
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered_plugins
            mock_loader_class.return_value = mock_loader

            mock_downloader = mock.MagicMock()
            mock_downloader.get_plugin_source.return_value = None
            mock_downloader.download_and_install.side_effect = DownloadError(
                "Network error"
            )
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(cli, ["plugin", "update", "tokenscanner"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to update tokenscanner" in result.output

    def test_update_plugin_not_available_error(self, cli_fs_runner):
        """
        GIVEN getting download info fails with PluginNotAvailableError
        WHEN running 'ggshield plugin update <plugin>'
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
                    latest_version="2.0.0",
                    reason=None,
                ),
            ],
            features={},
        )

        mock_discovered_plugins = [
            DiscoveredPlugin(
                name="tokenscanner",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
        ]

        with (
            mock.patch(
                "ggshield.cmd.plugin.update.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.update.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch("ggshield.cmd.plugin.update.PluginLoader") as mock_loader_class,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginDownloader"
            ) as mock_downloader_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.get_download_info.side_effect = (
                PluginNotAvailableError("tokenscanner", "Upgrade required")
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered_plugins
            mock_loader_class.return_value = mock_loader

            mock_downloader = mock.MagicMock()
            mock_downloader.get_plugin_source.return_value = None
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(cli, ["plugin", "update", "tokenscanner"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to update tokenscanner" in result.output

    def test_update_generic_error(self, cli_fs_runner):
        """
        GIVEN an unexpected error occurs during update
        WHEN running 'ggshield plugin update <plugin>'
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
                    latest_version="2.0.0",
                    reason=None,
                ),
            ],
            features={},
        )

        mock_discovered_plugins = [
            DiscoveredPlugin(
                name="tokenscanner",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
        ]

        mock_download_info = PluginDownloadInfo(
            download_url="https://example.com/plugin.whl",
            filename="tokenscanner-2.0.0.whl",
            sha256="abc123",
            version="2.0.0",
            expires_at="2099-12-31T23:59:59Z",
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.update.create_client_from_config"
            ) as mock_create_client,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginAPIClient"
            ) as mock_plugin_api_client_class,
            mock.patch(
                "ggshield.cmd.plugin.update.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch("ggshield.cmd.plugin.update.PluginLoader") as mock_loader_class,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginDownloader"
            ) as mock_downloader_class,
        ):
            mock_client = mock.MagicMock()
            mock_create_client.return_value = mock_client

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.get_download_info.return_value = mock_download_info
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered_plugins
            mock_loader_class.return_value = mock_loader

            mock_downloader = mock.MagicMock()
            mock_downloader.get_plugin_source.return_value = None
            mock_downloader.download_and_install.side_effect = Exception(
                "Unexpected error"
            )
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(cli, ["plugin", "update", "tokenscanner"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to update tokenscanner" in result.output
