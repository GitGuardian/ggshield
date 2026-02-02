"""
Tests for the enterprise plugin management commands (enable/disable/uninstall).
"""

from unittest import mock

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode


class TestPluginEnable:
    """Tests for 'ggshield plugin enable' command."""

    def test_enable_installed_plugin(self, cli_fs_runner):
        """
        GIVEN a plugin is installed
        WHEN running 'ggshield plugin enable <plugin>'
        THEN the plugin is enabled and config is saved
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.manage.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.manage.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.is_installed.return_value = True
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli, ["plugin", "enable", "testplugin"], catch_exceptions=False
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Enabled plugin: testplugin" in result.output
        mock_config.enable_plugin.assert_called_once_with("testplugin")
        mock_config.save.assert_called_once()

    def test_enable_not_installed_plugin(self, cli_fs_runner):
        """
        GIVEN a plugin is NOT installed
        WHEN running 'ggshield plugin enable <plugin>'
        THEN an error is shown
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.manage.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.manage.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch("ggshield.core.plugin.loader.PluginLoader") as mock_loader_class,
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.is_installed.return_value = False
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = []
            mock_loader_class.return_value = mock_loader

            result = cli_fs_runner.invoke(cli, ["plugin", "enable", "notinstalled"])

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "not installed" in result.output

    def test_enable_entry_point_plugin(self, cli_fs_runner):
        """
        GIVEN a plugin is installed via entry point (pip)
        WHEN running 'ggshield plugin enable <plugin>'
        THEN the plugin is enabled
        """
        from ggshield.core.plugin.loader import DiscoveredPlugin

        with (
            mock.patch(
                "ggshield.cmd.plugin.manage.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.manage.EnterpriseConfig"
            ) as mock_config_class,
            mock.patch("ggshield.core.plugin.loader.PluginLoader") as mock_loader_class,
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.is_installed.return_value = False
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            # Plugin discovered via entry point
            mock_plugins = [
                DiscoveredPlugin(
                    name="pipplugin",
                    entry_point=mock.MagicMock(),
                    wheel_path=None,
                    is_installed=True,
                    is_enabled=False,
                    version="1.0.0",
                ),
            ]
            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_plugins
            mock_loader_class.return_value = mock_loader

            result = cli_fs_runner.invoke(
                cli, ["plugin", "enable", "pipplugin"], catch_exceptions=False
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Enabled plugin: pipplugin" in result.output


class TestPluginDisable:
    """Tests for 'ggshield plugin disable' command."""

    def test_disable_plugin(self, cli_fs_runner):
        """
        GIVEN a plugin is enabled
        WHEN running 'ggshield plugin disable <plugin>'
        THEN the plugin is disabled and config is saved
        """
        with mock.patch(
            "ggshield.cmd.plugin.manage.EnterpriseConfig"
        ) as mock_config_class:
            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli, ["plugin", "disable", "testplugin"], catch_exceptions=False
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Disabled plugin: testplugin" in result.output
        mock_config.disable_plugin.assert_called_once_with("testplugin")
        mock_config.save.assert_called_once()


class TestPluginUninstall:
    """Tests for 'ggshield plugin uninstall' command."""

    def test_uninstall_plugin_with_yes(self, cli_fs_runner):
        """
        GIVEN a plugin is installed
        WHEN running 'ggshield plugin uninstall <plugin> -y'
        THEN the plugin is uninstalled without confirmation
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.manage.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.manage.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.is_installed.return_value = True
            mock_downloader.uninstall.return_value = True
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "uninstall", "testplugin", "-y"],
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Uninstalled plugin: testplugin" in result.output
        mock_downloader.uninstall.assert_called_once_with("testplugin")
        mock_config.remove_plugin.assert_called_once_with("testplugin")
        mock_config.save.assert_called_once()

    def test_uninstall_plugin_confirmation(self, cli_fs_runner):
        """
        GIVEN a plugin is installed
        WHEN running 'ggshield plugin uninstall <plugin>' and confirming
        THEN the plugin is uninstalled
        """
        with (
            mock.patch(
                "ggshield.cmd.plugin.manage.PluginDownloader"
            ) as mock_downloader_class,
            mock.patch(
                "ggshield.cmd.plugin.manage.EnterpriseConfig"
            ) as mock_config_class,
        ):
            mock_downloader = mock.MagicMock()
            mock_downloader.is_installed.return_value = True
            mock_downloader.uninstall.return_value = True
            mock_downloader_class.return_value = mock_downloader

            mock_config = mock.MagicMock()
            mock_config_class.load.return_value = mock_config

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "uninstall", "testplugin"],
                input="y\n",
                catch_exceptions=False,
            )

        assert result.exit_code == ExitCode.SUCCESS
        assert "Uninstalled plugin: testplugin" in result.output

    def test_uninstall_not_installed(self, cli_fs_runner):
        """
        GIVEN a plugin is NOT installed
        WHEN running 'ggshield plugin uninstall <plugin>'
        THEN an error is shown
        """
        with mock.patch(
            "ggshield.cmd.plugin.manage.PluginDownloader"
        ) as mock_downloader_class:
            mock_downloader = mock.MagicMock()
            mock_downloader.is_installed.return_value = False
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(cli, ["plugin", "uninstall", "notinstalled"])

        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "not installed" in result.output

    def test_uninstall_abort_confirmation(self, cli_fs_runner):
        """
        GIVEN a plugin is installed
        WHEN running 'ggshield plugin uninstall <plugin>' and aborting
        THEN the plugin is NOT uninstalled
        """
        with mock.patch(
            "ggshield.cmd.plugin.manage.PluginDownloader"
        ) as mock_downloader_class:
            mock_downloader = mock.MagicMock()
            mock_downloader.is_installed.return_value = True
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "uninstall", "testplugin"],
                input="n\n",
            )

        # Aborted - exit code 1
        assert result.exit_code != ExitCode.SUCCESS
        mock_downloader.uninstall.assert_not_called()

    def test_uninstall_fails(self, cli_fs_runner):
        """
        GIVEN uninstalling a plugin fails
        WHEN running 'ggshield plugin uninstall <plugin> -y'
        THEN an error is shown
        """
        with mock.patch(
            "ggshield.cmd.plugin.manage.PluginDownloader"
        ) as mock_downloader_class:
            mock_downloader = mock.MagicMock()
            mock_downloader.is_installed.return_value = True
            mock_downloader.uninstall.return_value = False
            mock_downloader_class.return_value = mock_downloader

            result = cli_fs_runner.invoke(
                cli,
                ["plugin", "uninstall", "testplugin", "-y"],
            )

        assert result.exit_code == ExitCode.UNEXPECTED_ERROR
        assert "Failed to uninstall plugin" in result.output
