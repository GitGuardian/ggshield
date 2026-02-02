"""Tests for plugin loader."""

import importlib.metadata
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from ggshield.core.config.enterprise_config import EnterpriseConfig, PluginConfig
from ggshield.core.plugin.base import GGShieldPlugin, PluginMetadata
from ggshield.core.plugin.loader import PluginLoader, get_plugins_dir
from ggshield.core.plugin.registry import PluginRegistry


class MockPlugin(GGShieldPlugin):
    """A mock plugin for testing."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="mockplugin",
            version="1.0.0",
            display_name="Mock Plugin",
            description="A mock plugin for testing",
            min_ggshield_version="1.0.0",
        )

    def register(self, registry: PluginRegistry) -> None:
        pass


class TestPluginLoader:
    """Tests for PluginLoader."""

    def test_discover_plugins_empty(self, tmp_path: Path) -> None:
        """Test discovering plugins when none exist."""
        config = EnterpriseConfig()

        with patch.object(PluginLoader, "_get_entry_points", return_value=iter([])):
            with patch(
                "ggshield.core.plugin.loader.get_plugins_dir", return_value=tmp_path
            ):
                loader = PluginLoader(config)
                discovered = loader.discover_plugins()

        assert discovered == []

    def test_discover_plugins_from_local_wheel(self, tmp_path: Path) -> None:
        """Test discovering plugins from local wheel files."""
        config = EnterpriseConfig()

        # Create plugin directory with manifest
        plugin_dir = tmp_path / "testplugin"
        plugin_dir.mkdir()
        wheel_file = plugin_dir / "testplugin-1.0.0.whl"
        wheel_file.touch()
        manifest = {
            "plugin_name": "testplugin",
            "version": "1.0.0",
            "wheel_filename": "testplugin-1.0.0.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch.object(PluginLoader, "_get_entry_points", return_value=iter([])):
            with patch(
                "ggshield.core.plugin.loader.get_plugins_dir", return_value=tmp_path
            ):
                loader = PluginLoader(config)
                loader.plugins_dir = tmp_path
                discovered = loader.discover_plugins()

        assert len(discovered) == 1
        assert discovered[0].name == "testplugin"
        assert discovered[0].version == "1.0.0"
        assert discovered[0].is_installed is True

    def test_is_enabled_default(self) -> None:
        """Test that plugins are disabled by default."""
        config = EnterpriseConfig()
        loader = PluginLoader(config)

        assert loader._is_enabled("any-plugin") is False

    def test_is_enabled_explicit_enabled(self) -> None:
        """Test checking explicitly enabled plugin."""
        config = EnterpriseConfig(plugins={"test-plugin": PluginConfig(enabled=True)})
        loader = PluginLoader(config)

        assert loader._is_enabled("test-plugin") is True

    def test_is_enabled_explicit_disabled(self) -> None:
        """Test checking explicitly disabled plugin."""
        config = EnterpriseConfig(plugins={"test-plugin": PluginConfig(enabled=False)})
        loader = PluginLoader(config)

        assert loader._is_enabled("test-plugin") is False

    def test_load_enabled_plugins_empty(self, tmp_path: Path) -> None:
        """Test loading plugins when none exist."""
        config = EnterpriseConfig()

        with patch.object(PluginLoader, "_get_entry_points", return_value=iter([])):
            with patch(
                "ggshield.core.plugin.loader.get_plugins_dir", return_value=tmp_path
            ):
                loader = PluginLoader(config)
                registry = loader.load_enabled_plugins()

        assert registry.get_all_plugins() == {}
        assert registry.get_commands() == []

    def test_load_enabled_plugins_skips_disabled(self, tmp_path: Path) -> None:
        """Test that disabled plugins are not loaded."""
        config = EnterpriseConfig(plugins={"testplugin": PluginConfig(enabled=False)})

        # Create plugin directory with manifest
        plugin_dir = tmp_path / "testplugin"
        plugin_dir.mkdir()
        wheel_file = plugin_dir / "testplugin-1.0.0.whl"
        wheel_file.touch()
        manifest = {
            "plugin_name": "testplugin",
            "version": "1.0.0",
            "wheel_filename": "testplugin-1.0.0.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch.object(PluginLoader, "_get_entry_points", return_value=iter([])):
            with patch(
                "ggshield.core.plugin.loader.get_plugins_dir", return_value=tmp_path
            ):
                loader = PluginLoader(config)
                loader.plugins_dir = tmp_path
                registry = loader.load_enabled_plugins()

        # Plugin should not be loaded because it's disabled
        assert registry.get_plugin("testplugin") is None

    def test_check_version_compatibility_compatible(self) -> None:
        """Test version compatibility check with compatible version."""
        config = EnterpriseConfig()
        loader = PluginLoader(config)

        metadata = PluginMetadata(
            name="test",
            version="1.0.0",
            display_name="Test",
            description="Test",
            min_ggshield_version="1.0.0",  # Very low version
        )

        assert loader._check_version_compatibility(metadata) is True

    def test_check_version_compatibility_incompatible(self) -> None:
        """Test version compatibility check with incompatible version."""
        config = EnterpriseConfig()
        loader = PluginLoader(config)

        metadata = PluginMetadata(
            name="test",
            version="1.0.0",
            display_name="Test",
            description="Test",
            min_ggshield_version="999.0.0",  # Very high version
        )

        assert loader._check_version_compatibility(metadata) is False

    def test_parse_entry_points_valid(self) -> None:
        """Test parsing valid entry points."""
        config = EnterpriseConfig()
        loader = PluginLoader(config)

        content = """
[ggshield.plugins]
myplugin = my_package.plugin:MyPlugin
"""
        result = loader._parse_entry_points(content)

        assert result == "my_package.plugin:MyPlugin"

    def test_parse_entry_points_missing_section(self) -> None:
        """Test parsing entry points without ggshield section."""
        config = EnterpriseConfig()
        loader = PluginLoader(config)

        content = """
[other.plugins]
myplugin = other:Plugin
"""
        result = loader._parse_entry_points(content)

        assert result is None

    def test_load_plugin_from_entry_point(self) -> None:
        """Test loading a plugin from entry point."""
        config = EnterpriseConfig()
        loader = PluginLoader(config)

        mock_ep = MagicMock()
        mock_ep.load.return_value = MockPlugin

        from ggshield.core.plugin.loader import DiscoveredPlugin

        discovered = DiscoveredPlugin(
            name="mockplugin",
            entry_point=mock_ep,
            wheel_path=None,
            is_installed=True,
            is_enabled=True,
            version="1.0.0",
        )

        plugin = loader._load_plugin(discovered)
        assert plugin is not None
        assert plugin.metadata.name == "mockplugin"

    def test_load_plugin_returns_none_when_no_source(self) -> None:
        """Test _load_plugin returns None when no entry point or wheel."""
        config = EnterpriseConfig()
        loader = PluginLoader(config)

        from ggshield.core.plugin.loader import DiscoveredPlugin

        discovered = DiscoveredPlugin(
            name="test",
            entry_point=None,
            wheel_path=None,
            is_installed=False,
            is_enabled=True,
            version=None,
        )

        plugin = loader._load_plugin(discovered)
        assert plugin is None

    def test_load_from_entry_point(self) -> None:
        """Test _load_from_entry_point method."""
        config = EnterpriseConfig()
        loader = PluginLoader(config)

        mock_ep = MagicMock()
        mock_ep.load.return_value = MockPlugin

        plugin = loader._load_from_entry_point(mock_ep)
        assert plugin is not None
        assert isinstance(plugin, MockPlugin)

    def test_load_enabled_plugins_with_entry_point(self, tmp_path: Path) -> None:
        """Test loading plugins from entry points."""
        config = EnterpriseConfig(plugins={"mockplugin": PluginConfig(enabled=True)})

        mock_ep = MagicMock()
        mock_ep.name = "mockplugin"
        mock_ep.value = "test_module:MockPlugin"
        mock_ep.load.return_value = MockPlugin

        with patch.object(
            PluginLoader, "_get_entry_points", return_value=iter([mock_ep])
        ):
            with patch(
                "ggshield.core.plugin.loader.get_plugins_dir", return_value=tmp_path
            ):
                loader = PluginLoader(config)
                registry = loader.load_enabled_plugins()

        assert registry.get_plugin("mockplugin") is not None

    def test_load_enabled_plugins_handles_load_exception(self, tmp_path: Path) -> None:
        """Test that load_enabled_plugins handles exceptions gracefully."""
        config = EnterpriseConfig(plugins={"badplugin": PluginConfig(enabled=True)})

        mock_ep = MagicMock()
        mock_ep.name = "badplugin"
        mock_ep.value = "bad_module:BadPlugin"
        mock_ep.load.side_effect = ImportError("Module not found")

        with patch.object(
            PluginLoader, "_get_entry_points", return_value=iter([mock_ep])
        ):
            with patch(
                "ggshield.core.plugin.loader.get_plugins_dir", return_value=tmp_path
            ):
                loader = PluginLoader(config)
                registry = loader.load_enabled_plugins()

        # Should not crash, just skip the bad plugin
        assert registry.get_plugin("badplugin") is None

    def test_load_enabled_plugins_skips_incompatible_version(
        self, tmp_path: Path
    ) -> None:
        """Test that plugins with incompatible version are skipped."""
        config = EnterpriseConfig(plugins={"incompatible": PluginConfig(enabled=True)})

        class IncompatiblePlugin(GGShieldPlugin):
            @property
            def metadata(self) -> PluginMetadata:
                return PluginMetadata(
                    name="incompatible",
                    version="1.0.0",
                    display_name="Incompatible",
                    description="Test",
                    min_ggshield_version="999.0.0",
                )

            def register(self, registry: PluginRegistry) -> None:
                pass

        mock_ep = MagicMock()
        mock_ep.name = "incompatible"
        mock_ep.value = "test:IncompatiblePlugin"
        mock_ep.load.return_value = IncompatiblePlugin

        with patch.object(
            PluginLoader, "_get_entry_points", return_value=iter([mock_ep])
        ):
            with patch(
                "ggshield.core.plugin.loader.get_plugins_dir", return_value=tmp_path
            ):
                loader = PluginLoader(config)
                registry = loader.load_enabled_plugins()

        assert registry.get_plugin("incompatible") is None

    def test_get_entry_point_version(self) -> None:
        """Test getting version from entry point."""
        config = EnterpriseConfig()
        loader = PluginLoader(config)

        mock_ep = MagicMock()
        mock_ep.value = "ggshield.core.plugin:TestPlugin"

        with patch(
            "ggshield.core.plugin.loader.importlib.metadata.distribution"
        ) as mock_dist:
            mock_dist.return_value.version = "1.2.3"
            version = loader._get_entry_point_version(mock_ep)

        assert version == "1.2.3"

    def test_get_entry_point_version_not_found(self) -> None:
        """Test getting version when package not found."""
        config = EnterpriseConfig()
        loader = PluginLoader(config)

        mock_ep = MagicMock()
        mock_ep.value = "nonexistent_package:Plugin"

        with patch(
            "ggshield.core.plugin.loader.importlib.metadata.distribution"
        ) as mock_dist:
            mock_dist.side_effect = importlib.metadata.PackageNotFoundError()
            version = loader._get_entry_point_version(mock_ep)

        assert version is None

    def test_scan_local_wheels_skips_non_directories(self, tmp_path: Path) -> None:
        """Test that _scan_local_wheels skips non-directory entries."""
        config = EnterpriseConfig()

        # Create a file instead of directory
        (tmp_path / "not_a_dir.txt").touch()

        with patch(
            "ggshield.core.plugin.loader.get_plugins_dir", return_value=tmp_path
        ):
            loader = PluginLoader(config)
            loader.plugins_dir = tmp_path
            wheels = list(loader._scan_local_wheels())

        assert wheels == []

    def test_scan_local_wheels_skips_invalid_manifest(self, tmp_path: Path) -> None:
        """Test that _scan_local_wheels skips directories with invalid manifest."""
        config = EnterpriseConfig()

        # Create plugin directory with invalid JSON manifest
        plugin_dir = tmp_path / "badplugin"
        plugin_dir.mkdir()
        (plugin_dir / "manifest.json").write_text("not valid json")

        with patch(
            "ggshield.core.plugin.loader.get_plugins_dir", return_value=tmp_path
        ):
            loader = PluginLoader(config)
            loader.plugins_dir = tmp_path
            wheels = list(loader._scan_local_wheels())

        assert wheels == []

    def test_scan_local_wheels_skips_missing_wheel(self, tmp_path: Path) -> None:
        """Test that _scan_local_wheels skips when wheel file doesn't exist."""
        config = EnterpriseConfig()

        # Create plugin directory with manifest but no wheel
        plugin_dir = tmp_path / "testplugin"
        plugin_dir.mkdir()
        manifest = {
            "plugin_name": "testplugin",
            "version": "1.0.0",
            "wheel_filename": "nonexistent.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.loader.get_plugins_dir", return_value=tmp_path
        ):
            loader = PluginLoader(config)
            loader.plugins_dir = tmp_path
            wheels = list(loader._scan_local_wheels())

        assert wheels == []

    def test_discover_plugins_from_entry_point(self, tmp_path: Path) -> None:
        """Test discovering plugins from entry points."""
        config = EnterpriseConfig()

        mock_ep = MagicMock()
        mock_ep.name = "testplugin"
        mock_ep.value = "test_module:TestPlugin"

        with patch.object(
            PluginLoader, "_get_entry_points", return_value=iter([mock_ep])
        ):
            with patch.object(
                PluginLoader, "_get_entry_point_version", return_value="2.0.0"
            ):
                with patch(
                    "ggshield.core.plugin.loader.get_plugins_dir", return_value=tmp_path
                ):
                    loader = PluginLoader(config)
                    discovered = loader.discover_plugins()

        assert len(discovered) == 1
        assert discovered[0].name == "testplugin"
        assert discovered[0].entry_point == mock_ep
        assert discovered[0].version == "2.0.0"

    def test_check_version_compatibility_parse_error(self) -> None:
        """Test version compatibility returns True on parse error."""
        config = EnterpriseConfig()
        loader = PluginLoader(config)

        metadata = PluginMetadata(
            name="test",
            version="1.0.0",
            display_name="Test",
            description="Test",
            min_ggshield_version="not-a-version",
        )

        # Should return True (permissive) when version parsing fails
        assert loader._check_version_compatibility(metadata) is True


class TestGetPluginsDir:
    """Tests for get_plugins_dir function."""

    @patch("ggshield.core.plugin.loader.get_data_dir")
    def test_returns_plugins_subdirectory(self, mock_data_dir: MagicMock) -> None:
        """Test that get_plugins_dir returns plugins subdirectory."""
        mock_data_dir.return_value = Path("/home/user/.local/share/ggshield")

        result = get_plugins_dir()

        assert result == Path("/home/user/.local/share/ggshield/plugins")
