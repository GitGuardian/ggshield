"""Tests for enterprise configuration."""

from pathlib import Path
from unittest.mock import patch

from ggshield.core.config.enterprise_config import EnterpriseConfig, PluginConfig


class TestPluginConfig:
    """Tests for PluginConfig dataclass."""

    def test_default_values(self) -> None:
        """Test default values for plugin config."""
        config = PluginConfig()

        assert config.enabled is True
        assert config.version is None
        assert config.auto_update is True

    def test_custom_values(self) -> None:
        """Test custom values for plugin config."""
        config = PluginConfig(enabled=False, version="1.2.3", auto_update=False)

        assert config.enabled is False
        assert config.version == "1.2.3"
        assert config.auto_update is False


class TestEnterpriseConfig:
    """Tests for EnterpriseConfig dataclass."""

    def test_empty_config(self) -> None:
        """Test creating empty enterprise config."""
        config = EnterpriseConfig()

        assert config.plugins == {}

    def test_enable_plugin(self) -> None:
        """Test enabling a plugin."""
        config = EnterpriseConfig()

        config.enable_plugin("test-plugin", version="1.0.0")

        assert "test-plugin" in config.plugins
        assert config.plugins["test-plugin"].enabled is True
        assert config.plugins["test-plugin"].version == "1.0.0"

    def test_enable_existing_plugin(self) -> None:
        """Test enabling an already configured plugin."""
        config = EnterpriseConfig(
            plugins={"test-plugin": PluginConfig(enabled=False, version="0.9.0")}
        )

        config.enable_plugin("test-plugin", version="1.0.0")

        assert config.plugins["test-plugin"].enabled is True
        assert config.plugins["test-plugin"].version == "1.0.0"

    def test_disable_plugin_missing_creates_config(self) -> None:
        """Test disabling a missing plugin creates a disabled config entry."""
        config = EnterpriseConfig()

        config.disable_plugin("test-plugin")

        assert "test-plugin" in config.plugins
        assert config.plugins["test-plugin"].enabled is False

    def test_disable_existing_plugin(self) -> None:
        """Test disabling an already configured plugin."""
        config = EnterpriseConfig(plugins={"test-plugin": PluginConfig(enabled=True)})

        config.disable_plugin("test-plugin")

        assert config.plugins["test-plugin"].enabled is False

    def test_is_plugin_enabled_default(self) -> None:
        """Test that plugins are enabled by default."""
        config = EnterpriseConfig()

        # Plugin not in config should be considered enabled by default
        assert config.is_plugin_enabled("nonexistent") is True

    def test_is_plugin_enabled_explicit(self) -> None:
        """Test checking if plugin is enabled explicitly."""
        config = EnterpriseConfig(
            plugins={
                "enabled-plugin": PluginConfig(enabled=True),
                "disabled-plugin": PluginConfig(enabled=False),
            }
        )

        assert config.is_plugin_enabled("enabled-plugin") is True
        assert config.is_plugin_enabled("disabled-plugin") is False

    def test_get_plugin_version(self) -> None:
        """Test getting plugin version."""
        config = EnterpriseConfig(
            plugins={"test-plugin": PluginConfig(version="1.2.3")}
        )

        assert config.get_plugin_version("test-plugin") == "1.2.3"
        assert config.get_plugin_version("nonexistent") is None

    def test_remove_plugin(self) -> None:
        """Test removing a plugin from config."""
        config = EnterpriseConfig(plugins={"test-plugin": PluginConfig()})

        result = config.remove_plugin("test-plugin")

        assert result is True
        assert "test-plugin" not in config.plugins

    def test_remove_nonexistent_plugin(self) -> None:
        """Test removing a plugin that doesn't exist."""
        config = EnterpriseConfig()

        result = config.remove_plugin("nonexistent")

        assert result is False

    def test_load_empty_file(self, tmp_path: Path) -> None:
        """Test loading from nonexistent file."""
        with patch(
            "ggshield.core.config.enterprise_config.get_enterprise_config_filepath"
        ) as mock_path:
            mock_path.return_value = tmp_path / "nonexistent.yaml"

            config = EnterpriseConfig.load()

            assert config.plugins == {}

    def test_load_and_save(self, tmp_path: Path) -> None:
        """Test loading and saving config."""
        config_path = tmp_path / "enterprise_config.yaml"

        with patch(
            "ggshield.core.config.enterprise_config.get_enterprise_config_filepath"
        ) as mock_path:
            mock_path.return_value = config_path

            # Create and save config
            config = EnterpriseConfig()
            config.enable_plugin("test-plugin", version="1.0.0")
            config.save()

            # Verify file exists
            assert config_path.exists()

            # Load and verify
            loaded = EnterpriseConfig.load()
            assert "test-plugin" in loaded.plugins
            assert loaded.plugins["test-plugin"].enabled is True
            assert loaded.plugins["test-plugin"].version == "1.0.0"

    def test_load_simple_format(self, tmp_path: Path) -> None:
        """Test loading config with simple boolean format."""
        config_path = tmp_path / "enterprise_config.yaml"
        config_path.write_text(
            """
plugins:
  enabled-plugin: true
  disabled-plugin: false
"""
        )

        with patch(
            "ggshield.core.config.enterprise_config.get_enterprise_config_filepath"
        ) as mock_path:
            mock_path.return_value = config_path

            config = EnterpriseConfig.load()

            assert config.plugins["enabled-plugin"].enabled is True
            assert config.plugins["disabled-plugin"].enabled is False
