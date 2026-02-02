"""
Plugin downloader - downloads and installs plugin wheels.
"""

import hashlib
import json
import logging
import shutil
from pathlib import Path
from typing import Optional

import requests

from ggshield.core.dirs import get_plugins_dir
from ggshield.core.plugin.client import PluginDownloadInfo


logger = logging.getLogger(__name__)


class DownloadError(Exception):
    """Error downloading or installing a plugin."""

    pass


class ChecksumMismatchError(DownloadError):
    """Downloaded file checksum doesn't match expected value."""

    def __init__(self, expected: str, actual: str):
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Checksum mismatch: expected {expected[:16]}..., got {actual[:16]}..."
        )


class PluginDownloader:
    """Downloads and installs plugin wheels."""

    def __init__(self) -> None:
        self.plugins_dir = get_plugins_dir(create=True)

    def download_and_install(
        self,
        download_info: PluginDownloadInfo,
        plugin_name: str,
    ) -> Path:
        """Download a plugin wheel and install it locally."""
        self._validate_plugin_name(plugin_name)

        plugin_dir = self.plugins_dir / plugin_name
        plugin_dir.mkdir(parents=True, exist_ok=True)

        wheel_path = plugin_dir / download_info.filename
        temp_path = plugin_dir / f"{download_info.filename}.tmp"

        try:
            logger.info("Downloading %s...", download_info.filename)
            response = requests.get(download_info.download_url, stream=True)
            response.raise_for_status()

            sha256_hash = hashlib.sha256()
            with open(temp_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    sha256_hash.update(chunk)

            computed_hash = sha256_hash.hexdigest()
            if computed_hash.lower() != download_info.sha256.lower():
                temp_path.unlink()
                raise ChecksumMismatchError(download_info.sha256, computed_hash)

            manifest = {
                "plugin_name": plugin_name,
                "version": download_info.version,
                "wheel_filename": download_info.filename,
                "sha256": download_info.sha256,
            }
            manifest_path = plugin_dir / "manifest.json"
            manifest_path.write_text(json.dumps(manifest, indent=2))

            temp_path.rename(wheel_path)

            logger.info("Installed %s v%s", plugin_name, download_info.version)

            return wheel_path

        except requests.RequestException as e:
            if temp_path.exists():
                temp_path.unlink()
            raise DownloadError(f"Failed to download plugin: {e}") from e

    def uninstall(self, plugin_name: str) -> bool:
        """Uninstall a plugin."""
        if not self._is_valid_plugin_name(plugin_name):
            logger.warning("Invalid plugin name: %s", plugin_name)
            return False

        plugin_dir = self.plugins_dir / plugin_name
        if not plugin_dir.exists():
            return False

        shutil.rmtree(plugin_dir)

        logger.info("Uninstalled plugin: %s", plugin_name)
        return True

    def get_installed_version(self, plugin_name: str) -> Optional[str]:
        """Get the installed version of a plugin."""
        if not self._is_valid_plugin_name(plugin_name):
            logger.warning("Invalid plugin name: %s", plugin_name)
            return None

        manifest_path = self.plugins_dir / plugin_name / "manifest.json"
        if not manifest_path.exists():
            return None

        try:
            manifest = json.loads(manifest_path.read_text())
            return manifest.get("version")
        except (json.JSONDecodeError, KeyError):
            return None

    def is_installed(self, plugin_name: str) -> bool:
        """Check if a plugin is installed."""
        return self.get_installed_version(plugin_name) is not None

    def get_wheel_path(self, plugin_name: str) -> Optional[Path]:
        """Get the path to an installed plugin's wheel file."""
        if not self._is_valid_plugin_name(plugin_name):
            logger.warning("Invalid plugin name: %s", plugin_name)
            return None

        manifest_path = self.plugins_dir / plugin_name / "manifest.json"
        if not manifest_path.exists():
            return None

        try:
            manifest = json.loads(manifest_path.read_text())
            wheel_filename = manifest.get("wheel_filename")
            if wheel_filename:
                wheel_path = self.plugins_dir / plugin_name / wheel_filename
                if wheel_path.exists():
                    return wheel_path
        except (json.JSONDecodeError, KeyError):
            pass

        return None

    @staticmethod
    def _is_valid_plugin_name(plugin_name: str) -> bool:
        """Check if plugin name is safe to use as a path segment."""
        if not plugin_name or plugin_name in {".", ".."}:
            return False
        if "/" in plugin_name or "\\" in plugin_name:
            return False
        if "\x00" in plugin_name:
            return False
        return True

    def _validate_plugin_name(self, plugin_name: str) -> None:
        """Validate plugin name and raise on unsafe values."""
        if not self._is_valid_plugin_name(plugin_name):
            raise DownloadError(f"Invalid plugin name: {plugin_name!r}")
