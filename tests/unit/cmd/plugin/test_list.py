"""
Tests for the enterprise list command.
"""

from pathlib import Path
from unittest import mock

import pytest

import ggshield.cmd.plugin.plugin_list as plugin_list_module
from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.core.plugin.client import PluginSource, PluginSourceType
from ggshield.core.plugin.loader import DiscoveredPlugin


def _run_list(cli_fs_runner, plugins, source_for_name=None, signature_label=None):
    """Invoke `ggshield plugin list` with mocked loader + downloader.

    ``source_for_name`` is a mapping of ``plugin name -> PluginSource | None``
    returned by the patched ``PluginDownloader.get_plugin_source``.
    """
    source_for_name = source_for_name or {}
    with (
        mock.patch.object(plugin_list_module, "PluginLoader") as mock_loader_class,
        mock.patch.object(
            plugin_list_module, "PluginDownloader"
        ) as mock_downloader_class,
    ):
        mock_loader = mock.MagicMock()
        mock_loader.discover_plugins.return_value = plugins
        mock_loader_class.return_value = mock_loader

        mock_downloader = mock.MagicMock()
        mock_downloader.get_plugin_source.side_effect = (
            lambda name: source_for_name.get(name)
        )
        mock_downloader.get_installed_signature_label.return_value = signature_label
        mock_downloader_class.return_value = mock_downloader

        return cli_fs_runner.invoke(cli, ["plugin", "list"])


class TestPluginList:
    """Tests for 'ggshield plugin list' command."""

    def test_list_no_plugins(self, cli_fs_runner):
        """
        GIVEN no plugins installed
        WHEN running 'ggshield plugin list'
        THEN it shows a message about no plugins
        """
        result = _run_list(cli_fs_runner, plugins=[])

        assert result.exit_code == ExitCode.SUCCESS
        assert "No plugins installed" in result.output
        assert "ggshield plugin status" in result.output

    def test_list_pip_plugin_without_wheel(self, cli_fs_runner):
        """
        GIVEN a plugin discovered only via a Python entry point (pip-installed,
              no on-disk wheel)
        WHEN running 'ggshield plugin list'
        THEN the source column is "pip" — ``get_plugin_source`` is not called
             because there's no wheel/manifest to consult.
        """
        plugins = [
            DiscoveredPlugin(
                name="testplugin",
                entry_point=mock.MagicMock(),
                wheel_path=None,
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
        ]

        result = _run_list(cli_fs_runner, plugins)

        assert result.exit_code == ExitCode.SUCCESS
        assert "testplugin" in result.output
        assert "enabled" in result.output
        assert "pip" in result.output

    @pytest.mark.parametrize(
        "source_type, expected_label",
        [
            (PluginSourceType.PLATFORM, "platform"),
            (PluginSourceType.LOCAL_FILE, "local file"),
            (PluginSourceType.URL, "url"),
            (PluginSourceType.GITHUB_RELEASE, "github release"),
            (PluginSourceType.GITHUB_ARTIFACT, "github artifact"),
        ],
    )
    def test_list_surfaces_manifest_source(
        self, cli_fs_runner, source_type, expected_label
    ):
        """
        GIVEN a wheel-installed plugin whose manifest records a ``source.type``
        WHEN running 'ggshield plugin list'
        THEN the source column mirrors the manifest value (with underscores
             replaced by spaces for readability) — tells the user WHERE the
             plugin came from, which the previous "local" label hid.
        """
        plugins = [
            DiscoveredPlugin(
                name="machine_scan",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="0.32.0",
            ),
        ]

        result = _run_list(
            cli_fs_runner,
            plugins,
            source_for_name={"machine_scan": PluginSource(type=source_type)},
            signature_label="signed (GitGuardian/satori)",
        )

        assert result.exit_code == ExitCode.SUCCESS
        assert "machine_scan" in result.output
        assert expected_label in result.output
        # The legacy label must not leak through for any recognised source type.
        assert ", local," not in result.output
        assert "signature: signed (GitGuardian/satori)" in result.output

    def test_list_legacy_wheel_without_manifest_falls_back_to_on_disk(
        self, cli_fs_runner
    ):
        """
        GIVEN a wheel on disk with no readable manifest
              (hand-dropped file — rare edge case)
        WHEN running 'ggshield plugin list'
        THEN the source column is "on-disk" rather than silently empty.
        """
        plugins = [
            DiscoveredPlugin(
                name="mystery_wheel",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=False,
                version="0.1.0",
            ),
        ]

        result = _run_list(
            cli_fs_runner,
            plugins,
            # No entry for "mystery_wheel" → get_plugin_source returns None.
        )

        assert result.exit_code == ExitCode.SUCCESS
        assert "mystery_wheel" in result.output
        assert "on-disk" in result.output

    def test_list_plugin_versions(self, cli_fs_runner):
        """
        GIVEN plugins with version info
        WHEN running 'ggshield plugin list'
        THEN it shows the version numbers
        """
        plugins = [
            DiscoveredPlugin(
                name="versioned",
                entry_point=mock.MagicMock(),
                wheel_path=None,
                is_installed=True,
                is_enabled=True,
                version="3.2.1",
            ),
        ]

        result = _run_list(cli_fs_runner, plugins)

        assert result.exit_code == ExitCode.SUCCESS
        assert "v3.2.1" in result.output
