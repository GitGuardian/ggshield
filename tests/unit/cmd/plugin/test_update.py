"""
Tests for the enterprise update command.
"""

from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.core.plugin.client import (
    PluginCatalog,
    PluginDownloadInfo,
    PluginInfo,
    PluginSourceType,
)
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

        mock_info = PluginDownloadInfo(
            filename="tokenscanner-2.0.0-py3-none-any.whl",
            sha256="abc123",
            version="2.0.0",
            size_bytes=100,
        )

        @contextmanager
        def fake_download_plugin(*args, **kwargs):
            yield mock_info, iter([b""])

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
            mock_plugin_api_client.download_plugin = fake_download_plugin
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
        mock_plugin_api_client.report_installation.assert_called_once_with(
            "tokenscanner", "2.0.0", mock.ANY, mock.ANY
        )

    def test_update_not_installed(self, cli_fs_runner):
        """
        GIVEN a plugin is not installed
        WHEN running 'ggshield plugin update <plugin>'
        THEN it shows an error
        """
        mock_catalog = PluginCatalog(
            plugins=[],
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

        mock_info_1 = PluginDownloadInfo(
            filename="plugin1-2.0.0-py3-none-any.whl",
            sha256="hash1",
            version="2.0.0",
            size_bytes=100,
        )
        mock_info_2 = PluginDownloadInfo(
            filename="plugin2-3.0.0-py3-none-any.whl",
            sha256="hash2",
            version="3.0.0",
            size_bytes=200,
        )
        _infos = iter([mock_info_1, mock_info_2])

        @contextmanager
        def fake_download_plugin(*args, **kwargs):
            yield next(_infos), iter([b""])

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
            mock_plugin_api_client.download_plugin = fake_download_plugin
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
        assert mock_plugin_api_client.report_installation.call_count == 2
        mock_plugin_api_client.report_installation.assert_any_call(
            "plugin1", "2.0.0", mock.ANY, mock.ANY
        )
        mock_plugin_api_client.report_installation.assert_any_call(
            "plugin2", "3.0.0", mock.ANY, mock.ANY
        )

    def test_update_api_error(self, cli_fs_runner):
        """
        GIVEN the API returns an error
        WHEN running 'ggshield plugin update --check'
        THEN it shows an error
        """
        from ggshield.core.plugin.client import PluginAPIError

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
            mock_plugin_api_client.get_available_plugins.side_effect = PluginAPIError(
                "API error"
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

            result = cli_fs_runner.invoke(cli, ["plugin", "update", "--check"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "API error" in result.output

    def test_update_connection_error(self, cli_fs_runner):
        """
        GIVEN connection to GitGuardian fails
        WHEN running 'ggshield plugin update --check'
        THEN it shows an error
        """
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
            mock_plugin_api_client.get_available_plugins.side_effect = Exception(
                "Connection refused"
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
            plugins=[],
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

    def test_update_no_downgrade(self, cli_fs_runner):
        """
        GIVEN the installed version is higher than the latest API version
        WHEN running 'ggshield plugin update --check'
        THEN it does NOT show an update (no downgrade)
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

        mock_discovered_plugins = [
            DiscoveredPlugin(
                name="tokenscanner",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="2.0.0",
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
        assert "Updates Available" not in result.output

    def test_update_download_error(self, cli_fs_runner):
        """
        GIVEN downloading a plugin update fails
        WHEN running 'ggshield plugin update <plugin>'
        THEN it shows an error
        """
        from ggshield.core.plugin.downloader import DownloadError

        mock_catalog = PluginCatalog(
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

        mock_info = PluginDownloadInfo(
            filename="tokenscanner-2.0.0-py3-none-any.whl",
            sha256="abc123",
            version="2.0.0",
            size_bytes=100,
        )

        @contextmanager
        def fake_download_plugin(*args, **kwargs):
            yield mock_info, iter([b""])

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
            mock_plugin_api_client.download_plugin = fake_download_plugin
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

            @contextmanager
            def fake_download_plugin_raises(*args, **kwargs):
                raise PluginNotAvailableError("tokenscanner", "Upgrade required")
                yield  # make it a generator

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.download_plugin = fake_download_plugin_raises
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

            mock_info = PluginDownloadInfo(
                filename="tokenscanner-2.0.0-py3-none-any.whl",
                sha256="abc123",
                version="2.0.0",
                size_bytes=100,
            )

            @contextmanager
            def fake_download_plugin(*args, **kwargs):
                yield mock_info, iter([b""])

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.download_plugin = fake_download_plugin
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

    def test_update_non_updatable_plugin(self, cli_fs_runner):
        """
        GIVEN a plugin installed from local file
        WHEN running 'ggshield plugin update <plugin>'
        THEN it shows the plugin cannot be auto-updated
        """
        from ggshield.core.plugin.client import PluginSource, PluginSourceType

        mock_discovered_plugins = [
            DiscoveredPlugin(
                name="localplugin",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
        ]

        mock_source = PluginSource(
            type=PluginSourceType.LOCAL_FILE,
            local_path="/path/to/local.whl",
        )

        with (
            mock.patch(
                "ggshield.cmd.plugin.update.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch("ggshield.cmd.plugin.update.PluginLoader") as mock_loader_class,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginDownloader"
            ) as mock_downloader_class,
        ):
            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered_plugins
            mock_loader_class.return_value = mock_loader

            mock_downloader = mock.MagicMock()
            mock_downloader.get_plugin_source.return_value = mock_source
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(cli, ["plugin", "update", "localplugin"])

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "cannot be auto-updated" in result.output

    def test_update_check_shows_non_updatable_plugins(self, cli_fs_runner):
        """
        GIVEN plugins installed from different sources
        WHEN running 'ggshield plugin update --check'
        THEN it shows non-updatable plugins separately
        """
        from ggshield.core.plugin.client import PluginSource, PluginSourceType

        mock_catalog = PluginCatalog(
            plugins=[],
        )

        mock_discovered_plugins = [
            DiscoveredPlugin(
                name="localplugin",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
        ]

        mock_source = PluginSource(
            type=PluginSourceType.LOCAL_FILE,
            local_path="/path/to/local.whl",
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
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered_plugins
            mock_loader_class.return_value = mock_loader

            mock_downloader = mock.MagicMock()
            mock_downloader.get_plugin_source.return_value = mock_source
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "update", "--check"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Cannot Auto-Update" in result.output
        assert "localplugin" in result.output
        # Humanised label, matching `ggshield plugin list`.
        assert "local file" in result.output
        assert "local_file" not in result.output

    def test_update_all_lists_non_updatable_when_nothing_to_update(self, cli_fs_runner):
        """
        GIVEN only non-auto-updatable plugins are installed
        WHEN running 'ggshield plugin update --all'
        THEN the 'Cannot Auto-Update' footer still appears so the user
             learns which plugins they need to reinstall manually,
             instead of an opaque 'All updatable plugins are already up
             to date' that hides the local-file installs.
        """
        from ggshield.core.plugin.client import PluginSource, PluginSourceType

        mock_catalog = PluginCatalog(plugins=[])
        mock_discovered_plugins = [
            DiscoveredPlugin(
                name="localplugin",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
        ]
        mock_source = PluginSource(
            type=PluginSourceType.LOCAL_FILE,
            local_path="/path/to/local.whl",
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
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config_class.load.return_value = mock.MagicMock()

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered_plugins
            mock_loader_class.return_value = mock_loader

            mock_downloader = mock.MagicMock()
            mock_downloader.get_plugin_source.return_value = mock_source
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "update", "--all"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Cannot Auto-Update" in result.output
        assert "localplugin" in result.output
        assert "local file" in result.output

    def test_update_plugins_not_enabled_exits_cleanly(self, cli_fs_runner):
        """
        GIVEN the platform has plugins disabled
        WHEN running 'ggshield plugin update --all'
        THEN it exits with a clean error (not a stack trace)
        """
        from ggshield.core.plugin.client import PluginsNotEnabledError

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
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.side_effect = (
                PluginsNotEnabledError()
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config_class.load.return_value = mock.MagicMock()

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered_plugins
            mock_loader_class.return_value = mock_loader

            mock_downloader = mock.MagicMock()
            mock_downloader.get_plugin_source.return_value = None
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(cli, ["plugin", "update", "--all"])

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "not available" in result.output.lower()
        assert "administrator" in result.output.lower()

    def test_update_catalog_failure_does_not_abort_github_release_check(
        self, cli_fs_runner
    ):
        """
        GIVEN one platform plugin and one github_release plugin installed,
              and the GitGuardian catalog fetch fails
        WHEN running 'ggshield plugin update --check'
        THEN the github_release plugin is still checked for updates and the
             command exits cleanly, instead of the platform-side failure
             killing the whole invocation.
        """
        from ggshield.core.plugin.client import (
            PluginAPIError,
            PluginSource,
            PluginSourceType,
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
            DiscoveredPlugin(
                name="ghplugin",
                entry_point=None,
                wheel_path=Path("/path/to/gh.whl"),
                is_installed=True,
                is_enabled=True,
                version="0.5.0",
            ),
        ]

        def fake_get_plugin_source(name):
            if name == "ghplugin":
                return PluginSource(
                    type=PluginSourceType.GITHUB_RELEASE,
                    github_repo="owner/ghplugin",
                )
            return None

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
            mock.patch(
                "ggshield.cmd.plugin.update._check_github_release_update",
                return_value={
                    "tag_name": "v0.6.0",
                    "assets": [
                        {
                            "name": "ghplugin-0.6.0-py3-none-any.whl",
                            "browser_download_url": "https://example.com/gh.whl",
                        }
                    ],
                },
            ),
        ):
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.side_effect = PluginAPIError(
                "catalog down"
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config_class.load.return_value = mock.MagicMock()

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered_plugins
            mock_loader_class.return_value = mock_loader

            mock_downloader = mock.MagicMock()
            mock_downloader.get_plugin_source.side_effect = fake_get_plugin_source
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(cli, ["plugin", "update", "--check"])

        assert result.exit_code == ExitCode.SUCCESS
        # Catalog failure surfaced as a warning, not a fatal error
        assert "catalog down" in result.output
        assert "Skipping GitGuardian-hosted plugin updates" in result.output
        # github_release plugin still produced an update entry
        assert "ghplugin" in result.output
        assert "0.5.0" in result.output and "0.6.0" in result.output


class TestUpdateHelperFunctions:
    """Tests for update command helper functions."""

    def test_check_github_release_update_success(self):
        """Test checking GitHub release returns latest release."""
        from ggshield.cmd.plugin.update import _check_github_release_update

        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "tag_name": "v2.0.0",
            "assets": [],
        }

        with mock.patch("requests.get", return_value=mock_response):
            result = _check_github_release_update("owner/repo")

        assert result is not None
        assert result["tag_name"] == "v2.0.0"

    def test_check_github_release_update_failure(self):
        """Test checking GitHub release handles errors."""
        from ggshield.cmd.plugin.update import _check_github_release_update

        mock_response = mock.MagicMock()
        mock_response.status_code = 404

        with mock.patch("requests.get", return_value=mock_response):
            result = _check_github_release_update("owner/repo")

        assert result is None

    def test_check_github_release_update_network_error(self):
        """Test checking GitHub release handles network errors."""
        import requests

        from ggshield.cmd.plugin.update import _check_github_release_update

        with mock.patch(
            "requests.get", side_effect=requests.RequestException("Network error")
        ):
            result = _check_github_release_update("owner/repo")

        assert result is None

    def test_find_wheel_asset_found(self):
        """Test finding wheel asset in release."""
        from ggshield.cmd.plugin.update import _find_wheel_asset

        release = {
            "assets": [
                {
                    "name": "README.md",
                    "browser_download_url": "https://example.com/readme",
                },
                {
                    "name": "plugin-1.0.0-py3-none-any.whl",
                    "browser_download_url": "https://example.com/plugin.whl",
                },
            ],
        }

        result = _find_wheel_asset(release)

        assert result == "https://example.com/plugin.whl"

    def test_find_wheel_asset_not_found(self):
        """Test finding wheel asset when none exists."""
        from ggshield.cmd.plugin.update import _find_wheel_asset

        release = {
            "assets": [
                {
                    "name": "README.md",
                    "browser_download_url": "https://example.com/readme",
                },
            ],
        }

        result = _find_wheel_asset(release)

        assert result is None

    def test_find_wheel_asset_empty_assets(self):
        """Test finding wheel asset with empty assets."""
        from ggshield.cmd.plugin.update import _find_wheel_asset

        release = {"assets": []}

        result = _find_wheel_asset(release)

        assert result is None


class TestUpdateUsesEntryPointConfigKey:
    """Regression for the round-3 follow-up: the update flow used to
    write ``enable_plugin(name, ...)`` directly, where ``name`` is the
    discover_plugins key (entry-point name when the wheel declares one,
    distribution name otherwise). When the catalog reference / loader key
    matched the entry-point name this was incidentally correct; when the
    update went through the GITHUB_RELEASE branch (where ``name`` could
    diverge from the wheel's actual entry-point name), the row written
    to enterprise_config drifted away from the loader's lookup key and
    the plugin was silently disabled after the upgrade.
    """

    def test_platform_update_keys_config_on_entry_point(
        self, cli_fs_runner, tmp_path: Path
    ) -> None:
        """
        GIVEN an installed plugin whose catalog reference happens to
            match the loader's discovered name (the common case for
            satori-python where reference == entry-point name)
            AND ``download_and_install`` writes a wheel whose embedded
            entry-point name happens to match
        WHEN the update flow completes
        THEN ``enable_plugin`` is called with the entry-point name
            extracted from the installed wheel — proving the wiring
            goes through ``resolve_config_key`` rather than passing
            ``name`` straight through.
        """
        import zipfile

        installed_wheel = tmp_path / "satori_python-2.0.0-py3-none-any.whl"
        with zipfile.ZipFile(installed_wheel, "w") as zf:
            zf.writestr(
                "satori_python-2.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\nmachine_scan = satori_python.plugin:Plugin\n",
            )

        mock_catalog = PluginCatalog(
            plugins=[
                PluginInfo(
                    name="machine_scan",
                    display_name="Machine Scan",
                    description="",
                    available=True,
                    latest_version="2.0.0",
                    reason=None,
                ),
            ],
        )
        mock_discovered = [
            DiscoveredPlugin(
                name="machine_scan",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
        ]
        mock_info = PluginDownloadInfo(
            filename="satori_python-2.0.0-py3-none-any.whl",
            sha256="a" * 64,
            version="2.0.0",
            size_bytes=10,
        )

        @contextmanager
        def fake_download_plugin(*args, **kwargs):
            yield mock_info, iter([b""])

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
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client.download_plugin = fake_download_plugin
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered
            mock_loader_class.return_value = mock_loader

            mock_downloader = mock.MagicMock()
            mock_downloader.get_plugin_source.return_value = None
            # ``download_and_install`` returns the installed wheel path;
            # this is what ``resolve_config_key`` reads the entry point
            # from. Point it at a real wheel on disk with the divergent
            # entry-point name.
            mock_downloader.download_and_install.return_value = installed_wheel
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "update", "machine_scan"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        mock_config.enable_plugin.assert_called_once_with(
            "machine_scan", version="2.0.0"
        )

    def test_github_release_update_keys_config_on_entry_point(
        self, cli_fs_runner, tmp_path: Path
    ) -> None:
        """
        GIVEN a plugin previously installed from a github_release and
            its loader key (``ghplugin``) differs from the entry-point
            name that the freshly downloaded wheel declares
            (``new_entry_point``)
        WHEN ``plugin update`` runs through the GITHUB_RELEASE branch
        THEN ``enable_plugin`` is called with the wheel's entry-point
            name — not with the loader key — so the row written matches
            what discover_plugins will look up after the upgrade.
        """
        import zipfile

        from ggshield.core.plugin.client import PluginSource

        installed_wheel = tmp_path / "ghplugin-2.0.0-py3-none-any.whl"
        with zipfile.ZipFile(installed_wheel, "w") as zf:
            zf.writestr(
                "ghplugin-2.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\nnew_entry_point = ghplugin.plugin:Plugin\n",
            )

        mock_discovered = [
            DiscoveredPlugin(
                name="ghplugin",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
        ]

        with (
            mock.patch("ggshield.cmd.plugin.update.create_client_from_config"),
            mock.patch("ggshield.cmd.plugin.update.PluginAPIClient"),
            mock.patch(
                "ggshield.cmd.plugin.update.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch("ggshield.cmd.plugin.update.PluginLoader") as mock_loader_class,
            mock.patch(
                "ggshield.cmd.plugin.update.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.update._check_github_release_update",
                return_value={
                    "tag_name": "v2.0.0",
                    "assets": [
                        {
                            "name": "ghplugin-2.0.0-py3-none-any.whl",
                            "browser_download_url": (
                                "https://github.com/owner/repo/releases/download/"
                                "v2.0.0/ghplugin-2.0.0-py3-none-any.whl"
                            ),
                        }
                    ],
                },
            ),
        ):
            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered
            mock_loader_class.return_value = mock_loader

            mock_downloader = mock.MagicMock()
            mock_downloader.get_plugin_source.return_value = PluginSource(
                type=PluginSourceType.GITHUB_RELEASE,
                url="https://github.com/owner/repo/releases/download/v1.0.0/p.whl",
                github_repo="owner/repo",
            )
            # Downloader returns the freshly installed wheel path; the
            # update flow MUST read its entry-point name (rather than
            # passing the loader key straight through).
            mock_downloader.download_from_github_release.return_value = (
                "ghplugin",
                "2.0.0",
                installed_wheel,
            )
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "update", "ghplugin"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        # The point of the regression: ``enable_plugin`` must use the
        # wheel's entry-point name (``new_entry_point``), NOT the loader
        # key (``ghplugin``). If this assertion sees ``ghplugin``, the
        # update path regressed back to passing ``name`` through verbatim
        # and the plugin would be silently disabled after the upgrade.
        mock_config.enable_plugin.assert_called_once_with(
            "new_entry_point", version="2.0.0"
        )


class TestUpdateCheckSkippedPlatform:
    """Regression for: when the catalog fetch fails and we degrade to
    github-only checks, the empty-results message must not pretend all
    plugins are up to date — platform plugins were never actually checked.
    """

    def test_check_acknowledges_skipped_platform(self, cli_fs_runner) -> None:
        """
        GIVEN one platform plugin and one github_release plugin, with a
            failing catalog fetch that degrades to github-only checks,
            and no GitHub-side updates available
        WHEN running ``ggshield plugin update --check``
        THEN the output explicitly says GitGuardian-hosted plugins were
            skipped instead of claiming everything is up to date.
        """
        from ggshield.core.plugin.client import (
            PluginAPIError,
            PluginSource,
            PluginSourceType,
        )

        mock_discovered_plugins = [
            DiscoveredPlugin(
                name="machine_scan",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
            DiscoveredPlugin(
                name="ghplugin",
                entry_point=None,
                wheel_path=Path("/path/to/gh-wheel"),
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
        ]

        def fake_get_plugin_source(name: str):
            if name == "ghplugin":
                return PluginSource(
                    type=PluginSourceType.GITHUB_RELEASE,
                    url="https://github.com/owner/repo/releases/download/v1.0.0/p.whl",
                    github_repo="owner/repo",
                )
            # Platform plugin (no explicit source recorded)
            return None

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
            mock.patch(
                "ggshield.cmd.plugin.update._check_github_release_update",
                return_value=None,
            ),
        ):
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.side_effect = PluginAPIError(
                "catalog fetch failed"
            )
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config_class.load.return_value = mock.MagicMock()

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_discovered_plugins
            mock_loader_class.return_value = mock_loader

            mock_downloader = mock.MagicMock()
            mock_downloader.get_plugin_source.side_effect = fake_get_plugin_source
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "update", "--check"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Skipping GitGuardian-hosted plugin updates" in result.output
        assert "GitGuardian-hosted plugins were skipped" in result.output
        # And we must NOT lie about state we didn't actually verify.
        assert "All updatable plugins are up to date." not in result.output

    def test_check_says_up_to_date_when_platform_actually_checked(
        self, cli_fs_runner
    ) -> None:
        """Counter-test: when the catalog fetch succeeds and confirms no
        updates, the message keeps the original wording so users with
        healthy backends still get the familiar terse output."""
        mock_catalog = PluginCatalog(
            plugins=[
                PluginInfo(
                    name="machine_scan",
                    display_name="Machine Scan",
                    description="",
                    available=True,
                    latest_version="1.0.0",
                    reason=None,
                ),
            ],
        )
        mock_discovered_plugins = [
            DiscoveredPlugin(
                name="machine_scan",
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
            mock_create_client.return_value = mock.MagicMock()

            mock_plugin_api_client = mock.MagicMock()
            mock_plugin_api_client.get_available_plugins.return_value = mock_catalog
            mock_plugin_api_client_class.return_value = mock_plugin_api_client

            mock_config_class.load.return_value = mock.MagicMock()

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
        assert "All updatable plugins are up to date." in result.output
        assert "skipped" not in result.output
