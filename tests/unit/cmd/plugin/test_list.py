"""
Tests for the enterprise list command.
"""

from pathlib import Path
from unittest import mock

import ggshield.cmd.plugin.plugin_list as plugin_list_module
from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode


class TestPluginList:
    """Tests for 'ggshield plugin list' command."""

    def test_list_no_plugins(self, cli_fs_runner):
        """
        GIVEN no plugins installed
        WHEN running 'ggshield plugin list'
        THEN it shows a message about no plugins
        """
        # Mock the loader to return empty list
        with mock.patch.object(plugin_list_module, "PluginLoader") as mock_loader_class:
            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = []
            mock_loader_class.return_value = mock_loader

            result = cli_fs_runner.invoke(cli, ["plugin", "list"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "No plugins installed" in result.output
        assert "ggshield plugin status" in result.output

    def test_list_with_plugins(self, cli_fs_runner):
        """
        GIVEN plugins are installed
        WHEN running 'ggshield plugin list'
        THEN it lists the plugins with their status
        """
        from ggshield.core.plugin.loader import DiscoveredPlugin

        # Create mock discovered plugins
        mock_plugins = [
            DiscoveredPlugin(
                name="testplugin",
                entry_point=mock.MagicMock(),
                wheel_path=None,
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
            DiscoveredPlugin(
                name="otherplugin",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=False,
                version="2.0.0",
            ),
        ]

        with mock.patch.object(plugin_list_module, "PluginLoader") as mock_loader_class:
            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_plugins
            mock_loader_class.return_value = mock_loader

            result = cli_fs_runner.invoke(cli, ["plugin", "list"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "Installed Plugins" in result.output
        assert "testplugin" in result.output
        assert "enabled" in result.output
        assert "pip" in result.output
        assert "otherplugin" in result.output
        assert "disabled" in result.output
        assert "local" in result.output

    def test_list_plugin_versions(self, cli_fs_runner):
        """
        GIVEN plugins with version info
        WHEN running 'ggshield plugin list'
        THEN it shows the version numbers
        """
        from ggshield.core.plugin.loader import DiscoveredPlugin

        mock_plugins = [
            DiscoveredPlugin(
                name="versioned",
                entry_point=mock.MagicMock(),
                wheel_path=None,
                is_installed=True,
                is_enabled=True,
                version="3.2.1",
            ),
        ]

        with mock.patch.object(plugin_list_module, "PluginLoader") as mock_loader_class:
            mock_loader = mock.MagicMock()
            mock_loader.discover_plugins.return_value = mock_plugins
            mock_loader_class.return_value = mock_loader

            result = cli_fs_runner.invoke(cli, ["plugin", "list"])

        assert result.exit_code == ExitCode.SUCCESS
        assert "v3.2.1" in result.output
