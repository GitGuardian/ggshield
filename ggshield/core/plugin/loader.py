"""
Plugin loader - discovers and loads plugins from entry points and local wheels.
"""

import importlib
import importlib.metadata
import logging
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple, TypedDict
from zipfile import ZipFile

from packaging import version as packaging_version

from ggshield import __version__ as ggshield_version
from ggshield.core.config.enterprise_config import EnterpriseConfig
from ggshield.core.dirs import get_cache_dir, get_plugins_dir
from ggshield.core.plugin.base import GGShieldPlugin, PluginMetadata
from ggshield.core.plugin.registry import PluginRegistry
from ggshield.core.plugin.signature import (
    SignatureStatus,
    SignatureVerificationError,
    SignatureVerificationMode,
    verify_wheel_signature,
)
from ggshield.core.plugin.trust import PluginTrustStore, compute_file_sha256


class WheelInfo(TypedDict):
    name: str
    version: str
    path: Path
    entry_point_name: Optional[str]


logger = logging.getLogger(__name__)

PLUGIN_ENTRY_POINT_GROUP = "ggshield.plugins"


def parse_entry_point_from_content(content: str) -> Optional[Tuple[str, str]]:
    """Parse entry_points.txt to find the ggshield.plugins entry.

    Returns (name, value) or None.
    """
    import configparser

    parser = configparser.ConfigParser()
    parser.optionxform = str  # type: ignore[assignment]  # preserve case
    parser.read_string(content)
    if not parser.has_section(PLUGIN_ENTRY_POINT_GROUP):
        return None
    items = parser.items(PLUGIN_ENTRY_POINT_GROUP)
    if not items:
        return None
    return items[0]


def read_entry_point_from_wheel(wheel_path: Path) -> Optional[Tuple[str, str]]:
    """Read ggshield.plugins entry point from a wheel.

    Returns (name, value) or None.
    """
    try:
        with ZipFile(wheel_path, "r") as zf:
            for zip_name in zf.namelist():
                if zip_name.endswith("entry_points.txt"):
                    content = zf.read(zip_name).decode("utf-8")
                    return parse_entry_point_from_content(content)
    except Exception as e:
        logger.debug("Failed to read wheel entry points: %s", e)
    return None


def resolve_config_key(wheel_path: Path, fallback: str) -> str:
    """Return the key to use when calling ``EnterpriseConfig.enable_plugin``.

    ``PluginLoader.discover_plugins`` keys wheel-installed plugins by
    their ``ggshield.plugins`` entry-point name when present, and only
    falls back to the wheel's distribution name when no entry point is
    declared. Enablement is checked against that same key. If install
    (or update) writes the config under the distribution name while
    discovery looks it up under the entry-point name, the plugin ends
    up silently disabled: install reports success but ``plugin list``
    shows it off and the plugin never loads.

    Reading the entry point from the wheel on the write side makes the
    two layers agree, regardless of whether the upstream package picked
    matching or divergent names. The fallback covers wheels that
    declare no entry point and wheels that error during decoding
    (``read_entry_point_from_wheel`` returns ``None`` in both cases —
    indistinguishable here, and the next step after ``enable_plugin``
    is the loader itself which will surface a real diagnostic).

    ``wheel_path`` is the installed wheel returned by the downloader
    and exists on every success path; the ``.exists()`` guard is
    defensive against future refactors that might pass a path before
    the wheel is on disk.
    """
    if not wheel_path.exists():
        return fallback
    entry_point = read_entry_point_from_wheel(wheel_path)
    if entry_point is None:
        return fallback
    return entry_point[0]


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

    def __init__(
        self,
        enterprise_config: EnterpriseConfig,
        signature_mode: Optional[SignatureVerificationMode] = None,
    ) -> None:
        self.enterprise_config = enterprise_config
        self.plugins_dir = get_plugins_dir()
        self.trust_store = PluginTrustStore(plugins_dir=self.plugins_dir)
        self.signature_mode = (
            signature_mode
            if signature_mode is not None
            else SignatureVerificationMode.STRICT
        )

    def discover_plugins(self) -> List[DiscoveredPlugin]:
        """Discover all available plugins from entry points and local wheels."""
        discovered: Dict[str, DiscoveredPlugin] = {}

        # 1. Discover from local wheels first and track their entry point names
        local_entry_point_names: set[str] = set()
        for wheel_info in self._scan_local_wheels():
            plugin_name: str = wheel_info["name"]
            wheel_path: Path = wheel_info["path"]
            wheel_version: str = wheel_info["version"]
            entry_point_name: Optional[str] = wheel_info["entry_point_name"]

            # Use entry point name as key if available, otherwise package name.
            # Older installs may have enabled the wheel distribution/package name
            # before ggshield learned the entry-point key. Treat that package name
            # as an alias so an installed+enabled plugin does not silently miss its
            # top-level commands.
            key = entry_point_name if entry_point_name else plugin_name
            if entry_point_name:
                local_entry_point_names.add(entry_point_name)

            is_enabled = self._is_enabled(key)
            if key not in self.enterprise_config.plugins and plugin_name != key:
                is_enabled = self._is_enabled(plugin_name)

            discovered[key] = DiscoveredPlugin(
                name=key,
                entry_point=None,
                wheel_path=wheel_path,
                is_installed=True,
                is_enabled=is_enabled,
                version=wheel_version,
            )

        # 2. Discover from entry points (skip if already found in local wheels)
        for ep in self._get_entry_points():
            plugin_name = ep.name
            # Skip if this entry point is provided by a local wheel
            if plugin_name in local_entry_point_names:
                continue
            discovered[plugin_name] = DiscoveredPlugin(
                name=plugin_name,
                entry_point=ep,
                wheel_path=None,
                is_installed=True,
                is_enabled=self._is_enabled(plugin_name),
                version=self._get_entry_point_version(ep),
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
        """Load a plugin from a local wheel file.

        Wheels are extracted to a directory before loading because Python
        cannot import native extensions (.so/.pyd) directly from zip files.
        """
        try:
            sig_info = verify_wheel_signature(wheel_path, self.signature_mode)
            if sig_info.status == SignatureStatus.VALID:
                logger.info(
                    "Signature valid for %s (identity: %s)",
                    wheel_path.name,
                    sig_info.identity,
                )
            elif sig_info.status in (
                SignatureStatus.MISSING,
                SignatureStatus.INVALID,
            ):
                logger.warning(
                    "Signature %s for %s: %s",
                    sig_info.status.value,
                    wheel_path.name,
                    sig_info.message or "",
                )
        except SignatureVerificationError as e:
            if (
                self.signature_mode == SignatureVerificationMode.STRICT
                and self._is_trusted_unsigned_plugin(wheel_path)
            ):
                logger.warning(
                    "Allowing trusted unsigned plugin %s after signature verification failed: %s",
                    wheel_path.name,
                    e,
                )
            else:
                logger.error(
                    "Signature verification failed for %s: %s",
                    wheel_path.name,
                    e,
                )
                return None

        # Extract wheel to a per-user cache directory instead of next to the
        # installed wheel. This keeps loading working when a wheel is installed
        # in a shared/root-owned data directory but the current user can still
        # read it.
        extract_dir = self._get_extract_dir(wheel_path)

        try:
            # In STRICT mode, always re-extract after verification so imports
            # come from the wheel bytes we just checked.
            if self.signature_mode == SignatureVerificationMode.STRICT or (
                not extract_dir.exists()
                or wheel_path.stat().st_mtime > extract_dir.stat().st_mtime
            ):
                if extract_dir.exists():
                    shutil.rmtree(extract_dir)
                extract_dir.parent.mkdir(parents=True, exist_ok=True)

                from ggshield.utils.archive import safe_unpack

                safe_unpack(wheel_path, extract_dir)

            self._prune_stale_extract_dirs(extract_dir)

            # Add extracted directory to sys.path
            extract_str = str(extract_dir)
            if extract_str not in sys.path:
                sys.path.append(extract_str)

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

    def _prune_stale_extract_dirs(self, keep_dir: Path) -> None:
        """Remove stale extraction dirs for the same plugin cache bucket."""
        parent = keep_dir.parent
        if not parent.exists():
            return

        for path in parent.iterdir():
            if path == keep_dir or not path.is_dir():
                continue
            if not path.name.endswith("_extracted"):
                continue
            try:
                shutil.rmtree(path)
            except OSError as exc:
                logger.debug(
                    "Failed to remove stale plugin extraction dir %s: %s", path, exc
                )

    def _get_extract_cache_dir(self) -> Path:
        """Return the cache dir used for extracted plugin wheels.

        `sudo -E` on Unix can preserve a non-root HOME, which makes platformdirs
        point root at the invoking user's cache dir. Do not create root-owned
        extraction trees there: use root's own cache unless GG_CACHE_DIR was set
        explicitly.
        """
        if os.environ.get("GG_CACHE_DIR"):
            return get_cache_dir()

        if sys.platform != "win32" and hasattr(os, "geteuid") and os.geteuid() == 0:
            home = os.environ.get("HOME")
            try:
                if home and Path(home).exists() and Path(home).stat().st_uid != 0:
                    import pwd

                    root_home = Path(pwd.getpwuid(0).pw_dir)
                    if sys.platform == "darwin":
                        return root_home / "Library" / "Caches" / "ggshield"
                    return root_home / ".cache" / "ggshield"
            except (KeyError, OSError):
                pass

        return get_cache_dir()

    def _get_extract_dir(self, wheel_path: Path) -> Path:
        """Return the per-user extraction directory for an installed wheel."""
        wheel_hash = compute_file_sha256(wheel_path)[:16]
        return (
            self._get_extract_cache_dir()
            / "plugins"
            / wheel_path.parent.name
            / f"{wheel_path.stem}-{wheel_hash}_extracted"
        )

    def _is_trusted_unsigned_plugin(self, wheel_path: Path) -> bool:
        """Return True when the current wheel hash matches a persisted trust record."""
        plugin_name = wheel_path.parent.name
        wheel_sha256 = compute_file_sha256(wheel_path)
        if self.trust_store.is_trusted(plugin_name, wheel_sha256):
            return True

        if self.trust_store.get_record(plugin_name) is not None:
            logger.warning(
                "Stored trust for %s does not match the current wheel hash, refusing to load it",
                plugin_name,
            )
        return False

    def _read_wheel_entry_point(self, wheel_path: Path) -> Optional[str]:
        """Read the ggshield.plugins entry point value from a wheel's metadata."""
        result = read_entry_point_from_wheel(wheel_path)
        return result[1] if result else None

    def _read_wheel_entry_point_name(self, wheel_path: Path) -> Optional[str]:
        """Read the entry point name from a wheel's entry_points.txt."""
        result = read_entry_point_from_wheel(wheel_path)
        return result[0] if result else None

    def _get_entry_points(self) -> Iterator[importlib.metadata.EntryPoint]:
        """Get all entry points in the ggshield.plugins group."""
        if sys.version_info >= (3, 10):
            eps = importlib.metadata.entry_points(group=PLUGIN_ENTRY_POINT_GROUP)
            yield from eps
        else:
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
                        # Extract entry point name from wheel for deduplication
                        entry_point_name = self._read_wheel_entry_point_name(wheel_path)
                        yield WheelInfo(
                            name=manifest["plugin_name"],
                            version=manifest["version"],
                            path=wheel_path,
                            entry_point_name=entry_point_name,
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
