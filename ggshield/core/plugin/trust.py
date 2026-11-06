"""Persistent trust records for explicitly accepted unsigned plugins."""

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from ggshield.core.dirs import get_plugins_dir

logger = logging.getLogger(__name__)

TRUST_STORE_FILENAME = "plugin_trust.json"
TRUST_STORE_VERSION = 1


@dataclass(frozen=True)
class TrustedPluginRecord:
    """A persisted trust exception for a specific plugin wheel."""

    sha256: str
    signature_status: str
    trusted_at: str


def get_trust_store_path(*, plugins_dir: Optional[Path] = None) -> Path:
    """Return the trust store path, outside the plugin directory."""
    base_plugins_dir = plugins_dir if plugins_dir is not None else get_plugins_dir()
    return base_plugins_dir.parent / TRUST_STORE_FILENAME


def compute_file_sha256(file_path: Path) -> str:
    """Compute the SHA256 of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


class PluginTrustStore:
    """Stores trust exceptions for exact plugin wheels accepted by the user."""

    def __init__(
        self,
        path: Optional[Path] = None,
        *,
        plugins_dir: Optional[Path] = None,
    ) -> None:
        self.path = path or get_trust_store_path(plugins_dir=plugins_dir)

    def trust_plugin(
        self,
        plugin_name: str,
        sha256: str,
        signature_status: str,
    ) -> None:
        """Persist trust for an exact plugin wheel hash."""
        data = self._load_data()
        data["plugins"][plugin_name] = {
            "sha256": sha256,
            "signature_status": signature_status,
            "trusted_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_data(data)

    def revoke_plugin(self, plugin_name: str) -> None:
        """Remove any persisted trust for a plugin."""
        data = self._load_data()
        if plugin_name not in data["plugins"]:
            return
        del data["plugins"][plugin_name]
        self._save_data(data)

    def get_record(self, plugin_name: str) -> Optional[TrustedPluginRecord]:
        """Return the stored trust record for a plugin, if any."""
        data = self._load_data()
        record = data["plugins"].get(plugin_name)
        if not isinstance(record, dict):
            return None

        sha256 = record.get("sha256")
        if not isinstance(sha256, str) or not sha256:
            return None

        signature_status = record.get("signature_status", "unknown")
        if not isinstance(signature_status, str):
            signature_status = "unknown"

        trusted_at = record.get("trusted_at", "")
        if not isinstance(trusted_at, str):
            trusted_at = ""

        return TrustedPluginRecord(
            sha256=sha256,
            signature_status=signature_status,
            trusted_at=trusted_at,
        )

    def is_trusted(self, plugin_name: str, sha256: str) -> bool:
        """Return True when the exact wheel hash was explicitly trusted."""
        record = self.get_record(plugin_name)
        return bool(record and record.sha256.lower() == sha256.lower())

    def _default_data(self) -> Dict[str, Any]:
        return {
            "version": TRUST_STORE_VERSION,
            "plugins": {},
        }

    def _load_data(self) -> Dict[str, Any]:
        if not self.path.exists():
            return self._default_data()

        try:
            data = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("Invalid plugin trust store at %s: %s", self.path, e)
            return self._default_data()

        plugins = data.get("plugins")
        if not isinstance(plugins, dict):
            logger.warning(
                "Invalid plugin trust store at %s: missing plugins map", self.path
            )
            return self._default_data()

        return {
            "version": data.get("version", TRUST_STORE_VERSION),
            "plugins": plugins,
        }

    def _save_data(self, data: Dict[str, Any]) -> None:
        plugins = data.get("plugins") or {}
        if not plugins:
            if self.path.exists():
                self.path.unlink()
            return

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2))
