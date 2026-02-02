"""
Plugin loader - discovers and loads plugins from entry points and local wheels.
"""

import importlib
import importlib.metadata
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, TypedDict
from zipfile import ZipFile

from ggshield import __version__ as ggshield_version
from ggshield.core.config.enterprise_config import EnterpriseConfig
from ggshield.core.dirs import get_plugins_dir
from ggshield.core.plugin.base import GGShieldPlugin, PluginMetadata
from ggshield.core.plugin.registry import PluginRegistry


try:
    from packaging import version as packaging_version
except ImportError:  # pragma: no cover
    packaging_version = None


class WheelInfo(TypedDict):
    name: str
    version: str
    path: Path


logger = logging.getLogger(__name__)

PLUGIN_ENTRY_POINT_GROUP = "ggshield.plugins"


@dataclass
class DiscoveredPlugin:
    """Information about a discovered plugin."""

    name: str
    entry_point: Optional[importlib.metadata.EntryPoint]
    wheel_path: Optional[Path]
    is_installed: bool
    is_enabled: bool
    version: Optional[str]


class PluginLoader:
    """Discovers and loads ggshield plugins from entry points and local wheels."""

    def __init__(self, enterprise_config: EnterpriseConfig) -> None:
        self.enterprise_config = enterprise_config
        self.plugins_dir = get_plugins_dir()

    def discover_plugins(self) -> List[DiscoveredPlugin]:
        """Discover all available plugins from entry points and local wheels."""
        discovered: Dict[str, DiscoveredPlugin] = {}
        for ep in self._get_entry_points():
            plugin_name = ep.name
            discovered[plugin_name] = DiscoveredPlugin(
                name=plugin_name,
                entry_point=ep,
                wheel_path=None,
                is_installed=True,
                is_enabled=self._is_enabled(plugin_name),
                version=self._get_entry_point_version(ep),
            )

        # 2. Discover from local wheels (may override entry points)
        for wheel_info in self._scan_local_wheels():
            plugin_name: str = wheel_info["name"]
            wheel_path: Path = wheel_info["path"]
            wheel_version: str = wheel_info["version"]
            discovered[plugin_name] = DiscoveredPlugin(
                name=plugin_name,
                entry_point=None,
                wheel_path=wheel_path,
                is_installed=True,
                is_enabled=self._is_enabled(plugin_name),
                version=wheel_version,
            )

        return list(discovered.values())

    def load_enabled_plugins(self) -> PluginRegistry:
        """Load all enabled plugins and return a populated registry."""
        registry = PluginRegistry()

        for discovered in self.discover_plugins():
            if not discovered.is_enabled:
                logger.debug("Skipping disabled plugin: %s", discovered.name)
                continue

            try:
                plugin = self._load_plugin(discovered)
                if plugin is None:
                    continue

                if not self._check_version_compatibility(plugin.metadata):
                    logger.warning(
                        "Plugin %s requires ggshield >= %s, skipping",
                        plugin.metadata.name,
                        plugin.metadata.min_ggshield_version,
                    )
                    continue

                plugin.on_load()
                plugin.register(registry)
                registry.register_plugin(plugin)

                logger.info(
                    "Loaded plugin: %s v%s",
                    plugin.metadata.name,
                    plugin.metadata.version,
                )

            except Exception as e:
                logger.warning("Failed to load plugin %s: %s", discovered.name, e)

        return registry

    def _load_plugin(self, discovered: DiscoveredPlugin) -> Optional[GGShieldPlugin]:
        """Load a single plugin from discovery info."""
        if discovered.wheel_path:
            return self._load_from_wheel(discovered.wheel_path)
        elif discovered.entry_point:
            return self._load_from_entry_point(discovered.entry_point)
        return None

    def _load_from_entry_point(
        self, ep: importlib.metadata.EntryPoint
    ) -> GGShieldPlugin:
        """Load a plugin from an entry point."""
        plugin_class = ep.load()
        return plugin_class()

    def _load_from_wheel(self, wheel_path: Path) -> Optional[GGShieldPlugin]:
        """Load a plugin from a local wheel file."""
        wheel_str = str(wheel_path)
        if wheel_str not in sys.path:
            sys.path.insert(0, wheel_str)

        try:
            entry_point_str = self._read_wheel_entry_point(wheel_path)
            if not entry_point_str:
                logger.warning("No entry point found in wheel: %s", wheel_path)
                return None

            module_name, class_name = entry_point_str.split(":")
            module = importlib.import_module(module_name)
            plugin_class = getattr(module, class_name)
            return plugin_class()
        except Exception as e:
            logger.warning("Failed to load wheel %s: %s", wheel_path, e)
            return None

    def _read_wheel_entry_point(self, wheel_path: Path) -> Optional[str]:
        """Read the ggshield.plugins entry point from a wheel's metadata."""
        try:
            with ZipFile(wheel_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith("entry_points.txt"):
                        content = zf.read(name).decode("utf-8")
                        return self._parse_entry_points(content)
        except Exception as e:
            logger.debug("Failed to read wheel entry points: %s", e)
        return None

    def _parse_entry_points(self, content: str) -> Optional[str]:
        """Parse entry_points.txt content to find ggshield.plugins entry."""
        in_section = False
        for line in content.splitlines():
            line = line.strip()
            if line == f"[{PLUGIN_ENTRY_POINT_GROUP}]":
                in_section = True
            elif line.startswith("["):
                in_section = False
            elif in_section and "=" in line:
                _, value = line.split("=", 1)
                return value.strip()
        return None

    def _get_entry_points(self) -> Iterator[importlib.metadata.EntryPoint]:
        """Get all entry points in the ggshield.plugins group."""
        try:
            eps = importlib.metadata.entry_points(group=PLUGIN_ENTRY_POINT_GROUP)
            yield from eps
        except TypeError:
            all_eps = importlib.metadata.entry_points()
            yield from all_eps.get(PLUGIN_ENTRY_POINT_GROUP, [])

    def _scan_local_wheels(self) -> Iterator[WheelInfo]:
        """Scan the plugins directory for installed wheels."""
        import json

        if not self.plugins_dir.exists():
            return

        for plugin_dir in self.plugins_dir.iterdir():
            if not plugin_dir.is_dir():
                continue

            manifest_path = plugin_dir / "manifest.json"
            if manifest_path.exists():
                try:
                    manifest = json.loads(manifest_path.read_text())
                    wheel_filename = manifest.get("wheel_filename", "")
                    wheel_path = plugin_dir / wheel_filename

                    if wheel_path.exists():
                        yield WheelInfo(
                            name=manifest["plugin_name"],
                            version=manifest["version"],
                            path=wheel_path,
                        )
                except (json.JSONDecodeError, KeyError) as e:
                    logger.warning("Invalid manifest in %s: %s", plugin_dir, e)

    def _is_enabled(self, plugin_name: str) -> bool:
        """Check if a plugin is enabled in config."""
        plugin_config = self.enterprise_config.plugins.get(plugin_name)
        if plugin_config is None:
            return False
        return plugin_config.enabled

    def _get_entry_point_version(
        self, ep: importlib.metadata.EntryPoint
    ) -> Optional[str]:
        """Get the version of a package providing an entry point."""
        try:
            module_path = ep.value.split(":")[0]
            package_name = module_path.split(".")[0]
            dist = importlib.metadata.distribution(package_name)
            return dist.version
        except (importlib.metadata.PackageNotFoundError, IndexError):
            return None

    def _check_version_compatibility(self, metadata: PluginMetadata) -> bool:
        """Check if plugin is compatible with current ggshield version."""
        if packaging_version is None:
            logger.error(
                "Cannot check plugin compatibility: 'packaging' is unavailable"
            )
            return False

        try:
            current = packaging_version.parse(ggshield_version)
            required = packaging_version.parse(metadata.min_ggshield_version)
            return current >= required
        except Exception as e:
            logger.error(
                "Failed to parse version for plugin %s (requires %s): %s",
                metadata.name,
                metadata.min_ggshield_version,
                e,
            )
            return False
