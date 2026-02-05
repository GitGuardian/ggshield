"""Tests for plugin loader."""

import importlib.metadata
import json
import sys
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
        """Test version compatibility returns False on parse error."""
        config = EnterpriseConfig()
        loader = PluginLoader(config)

        metadata = PluginMetadata(
            name="test",
            version="1.0.0",
            display_name="Test",
            description="Test",
            min_ggshield_version="not-a-version",
        )

        assert loader._check_version_compatibility(metadata) is False

    def test_parse_entry_point_name_valid(self) -> None:
        """Test parsing entry point name from entry_points.txt."""
        config = EnterpriseConfig()
        loader = PluginLoader(config)

        content = """
[ggshield.plugins]
my_plugin = my_package.plugin:MyPlugin
"""
        result = loader._parse_entry_point_name(content)

        assert result == "my_plugin"

    def test_parse_entry_point_name_missing_section(self) -> None:
        """Test parsing entry point name without ggshield section."""
        config = EnterpriseConfig()
        loader = PluginLoader(config)

        content = """
[other.plugins]
myplugin = other:Plugin
"""
        result = loader._parse_entry_point_name(content)

        assert result is None

    def test_read_wheel_entry_point_name(self, tmp_path: Path) -> None:
        """Test reading entry point name from wheel file."""
        import zipfile

        config = EnterpriseConfig()
        loader = PluginLoader(config)

        # Create a mock wheel file with entry_points.txt
        wheel_path = tmp_path / "test-1.0.0.whl"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr(
                "test-1.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\ntest_plugin = test.plugin:TestPlugin\n",
            )

        result = loader._read_wheel_entry_point_name(wheel_path)

        assert result == "test_plugin"

    def test_read_wheel_entry_point_name_no_entry_points(self, tmp_path: Path) -> None:
        """Test reading entry point name when wheel has no entry_points.txt."""
        import zipfile

        config = EnterpriseConfig()
        loader = PluginLoader(config)

        # Create a mock wheel file without entry_points.txt
        wheel_path = tmp_path / "test-1.0.0.whl"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr("test-1.0.0.dist-info/METADATA", "Name: test\nVersion: 1.0.0\n")

        result = loader._read_wheel_entry_point_name(wheel_path)

        assert result is None

    def test_discover_plugins_deduplicates_by_entry_point_name(
        self, tmp_path: Path
    ) -> None:
        """Test that local wheel takes precedence over pip entry point."""
        import zipfile

        config = EnterpriseConfig()

        # Create plugin directory with manifest and wheel
        plugin_dir = tmp_path / "package-name"
        plugin_dir.mkdir()
        wheel_file = plugin_dir / "package_name-1.0.0.whl"

        # Create wheel with entry point named "my_plugin"
        with zipfile.ZipFile(wheel_file, "w") as zf:
            zf.writestr(
                "package_name-1.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\nmy_plugin = package_name.plugin:Plugin\n",
            )

        manifest = {
            "plugin_name": "package-name",
            "version": "1.0.0",
            "wheel_filename": "package_name-1.0.0.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        # Mock a pip entry point with the same name "my_plugin"
        mock_ep = MagicMock()
        mock_ep.name = "my_plugin"
        mock_ep.value = "other_package:Plugin"

        with patch.object(
            PluginLoader, "_get_entry_points", return_value=iter([mock_ep])
        ):
            with patch(
                "ggshield.core.plugin.loader.get_plugins_dir", return_value=tmp_path
            ):
                loader = PluginLoader(config)
                loader.plugins_dir = tmp_path
                discovered = loader.discover_plugins()

        # Should only have one plugin (local wheel takes precedence)
        assert len(discovered) == 1
        assert discovered[0].name == "my_plugin"
        assert discovered[0].wheel_path == wheel_file
        assert discovered[0].entry_point is None  # Local wheel, not entry point

    def test_load_from_wheel_extracts_wheel(self, tmp_path: Path) -> None:
        """Test that _load_from_wheel extracts wheel to directory."""
        import zipfile

        config = EnterpriseConfig()
        loader = PluginLoader(config)

        # Create a mock wheel with a Python module
        wheel_path = tmp_path / "test_plugin-1.0.0.whl"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr(
                "test_plugin/__init__.py",
                "class TestPlugin: pass",
            )
            zf.writestr(
                "test_plugin-1.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\ntest = test_plugin:TestPlugin\n",
            )

        # Mock the import to avoid actual module loading
        with patch(
            "ggshield.core.plugin.loader.importlib.import_module"
        ) as mock_import:
            mock_module = MagicMock()
            mock_module.TestPlugin = MockPlugin
            mock_import.return_value = mock_module

            loader._load_from_wheel(wheel_path)

        # Verify extraction directory was created
        extract_dir = tmp_path / ".test_plugin-1.0.0_extracted"
        assert extract_dir.exists()
        assert (extract_dir / "test_plugin" / "__init__.py").exists()

    def test_load_from_wheel_handles_exception(self, tmp_path: Path) -> None:
        """Test that _load_from_wheel returns None on exception."""
        import zipfile

        config = EnterpriseConfig()
        loader = PluginLoader(config)

        # Create wheel with entry point
        wheel_path = tmp_path / "test-1.0.0.whl"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr(
                "test-1.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\ntest = test:Plugin\n",
            )

        # Module import will fail
        with patch(
            "ggshield.core.plugin.loader.importlib.import_module",
            side_effect=ImportError("Module not found"),
        ):
            result = loader._load_from_wheel(wheel_path)

        assert result is None

    def test_load_from_wheel_appends_to_sys_path(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Test extracted wheel directory is appended to sys.path."""
        import zipfile

        config = EnterpriseConfig()
        loader = PluginLoader(config)

        wheel_path = tmp_path / "test_plugin-1.0.0.whl"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr("test_plugin/__init__.py", "class TestPlugin: pass")
            zf.writestr(
                "test_plugin-1.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\ntest = test_plugin:TestPlugin\n",
            )

        initial_sys_path = ["/existing/path", *sys.path]
        monkeypatch.setattr(sys, "path", initial_sys_path)

        with patch(
            "ggshield.core.plugin.loader.importlib.import_module"
        ) as mock_import:
            mock_module = MagicMock()
            mock_module.TestPlugin = MockPlugin
            mock_import.return_value = mock_module

            loader._load_from_wheel(wheel_path)

        extract_dir = tmp_path / ".test_plugin-1.0.0_extracted"
        assert sys.path[0] == "/existing/path"
        assert str(extract_dir) in sys.path
        assert sys.path.index(str(extract_dir)) > 0


class TestGetPluginsDir:
    """Tests for get_plugins_dir function."""

    @patch("ggshield.core.dirs.get_data_dir")
    def test_returns_plugins_subdirectory(self, mock_data_dir: MagicMock) -> None:
        """Test that get_plugins_dir returns plugins subdirectory."""
        mock_data_dir.return_value = Path("/home/user/.local/share/ggshield")

        result = get_plugins_dir()

        assert result == Path("/home/user/.local/share/ggshield/plugins")
