"""
Plugin API client - fetches available plugins from GitGuardian API.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import requests
from pygitguardian import GGClient

from ggshield.core.plugin.platform import PlatformInfo, get_platform_info


class PluginSourceType(Enum):
    """Types of plugin sources."""

    GITGUARDIAN_API = "gitguardian_api"
    LOCAL_FILE = "local_file"
    URL = "url"
    GITHUB_RELEASE = "github_release"
    GITHUB_ARTIFACT = "github_artifact"


@dataclass
class PluginSource:
    """Information about where a plugin was installed from."""

    type: PluginSourceType
    url: Optional[str] = None
    github_repo: Optional[str] = None
    sha256: Optional[str] = None
    local_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: Dict[str, Any] = {"type": self.type.value}
        if self.url:
            result["url"] = self.url
        if self.github_repo:
            result["github_repo"] = self.github_repo
        if self.sha256:
            result["sha256"] = self.sha256
        if self.local_path:
            result["local_path"] = self.local_path
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PluginSource":
        """Create from dictionary."""
        return cls(
            type=PluginSourceType(data["type"]),
            url=data.get("url"),
            github_repo=data.get("github_repo"),
            sha256=data.get("sha256"),
            local_path=data.get("local_path"),
        )


@dataclass
class PluginInfo:
    """Information about an available plugin."""

    name: str
    display_name: str
    description: str
    available: bool
    latest_version: Optional[str]
    supported_platforms: List[str] = field(default_factory=list)
    reason: Optional[str] = None

    def is_platform_supported(self, platform: str, arch: str) -> bool:
        """Check if this plugin supports the given platform/arch."""
        if not self.supported_platforms:
            return True
        return (
            f"{platform}-{arch}" in self.supported_platforms
            or "any-any" in self.supported_platforms
        )


@dataclass
class PluginCatalog:
    """Catalog of available plugins for the account."""

    plan: str
    features: Dict[str, bool]
    plugins: List[PluginInfo]


@dataclass
class PluginDownloadInfo:
    """Information needed to download a plugin."""

    download_url: str
    filename: str
    sha256: str
    version: str
    expires_at: str
    signature_url: Optional[str] = None


class PluginAPIError(Exception):
    """Error communicating with the plugin API."""

    pass


class PluginNotAvailableError(Exception):
    """Plugin is not available for this account."""

    def __init__(self, plugin_name: str, reason: Optional[str] = None):
        self.plugin_name = plugin_name
        self.reason = reason
        message = f"Plugin '{plugin_name}' is not available"
        if reason:
            message += f": {reason}"
        super().__init__(message)


class PluginAPIClient:
    """Client for GitGuardian plugin API."""

    API_VERSION = "v1"

    def __init__(self, client: GGClient):
        self.client = client
        self.base_url = client.base_uri.rstrip("/")

    def get_available_plugins(self) -> PluginCatalog:
        """Fetch available plugins for the authenticated account."""
        platform_info = get_platform_info()

        try:
            response = self.client.session.get(
                f"{self.base_url}/{self.API_VERSION}/plugins",
                params={
                    "platform": platform_info.os,
                    "arch": platform_info.arch,
                },
                headers=self._get_headers(),
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise PluginAPIError(f"Failed to fetch plugins: {e}") from e

        data = response.json()

        account_data = data.get("account", {})
        current_platform = f"{platform_info.os}-{platform_info.arch}"

        return PluginCatalog(
            plan=account_data.get("plan", data.get("plan", "unknown")),
            features=account_data.get("features", data.get("features", {})),
            plugins=[
                PluginInfo(
                    name=p.get("name", "unknown"),
                    display_name=p.get("display_name", p.get("name", "Unknown")),
                    description=p.get("description", ""),
                    available=self._is_plugin_available(p, current_platform),
                    latest_version=p.get("latest_version"),
                    supported_platforms=p.get("supported_platforms", []),
                    reason=self._get_unavailable_reason(p, current_platform),
                )
                for p in data.get("plugins", [])
            ],
        )

    def get_download_info(
        self,
        plugin_name: str,
        version: Optional[str] = None,
        platform_info: Optional[PlatformInfo] = None,
    ) -> PluginDownloadInfo:
        """Get download URL for a plugin wheel."""
        resolved_platform_info: PlatformInfo
        if platform_info is None:
            resolved_platform_info = get_platform_info()
        else:
            resolved_platform_info = platform_info

        params: Dict[str, str] = {
            "platform": resolved_platform_info.os,
            "arch": resolved_platform_info.arch,
            "python_abi": resolved_platform_info.python_abi,
        }
        if version:
            params["version"] = version

        try:
            response = self.client.session.get(
                f"{self.base_url}/{self.API_VERSION}/plugins/{plugin_name}/download",
                params=params,
                headers=self._get_headers(),
            )

            if response.status_code == 403:
                raise PluginNotAvailableError(plugin_name)
            elif response.status_code == 404:
                raise PluginNotAvailableError(
                    plugin_name, "Plugin or version not found"
                )

            response.raise_for_status()

        except PluginNotAvailableError:
            raise
        except requests.RequestException as e:
            raise PluginAPIError(f"Failed to get download info: {e}") from e

        data = response.json()

        return PluginDownloadInfo(
            download_url=data["download_url"],
            filename=data["filename"],
            sha256=data["sha256"],
            version=data["version"],
            expires_at=data["expires_at"],
            signature_url=data.get("signature_url"),
        )

    def _is_plugin_available(
        self, plugin_data: Dict[str, Any], current_platform: str
    ) -> bool:
        if not plugin_data.get("available", True):
            return False
        supported = plugin_data.get("supported_platforms", [])
        if not supported:
            return True
        return current_platform in supported or "any-any" in supported

    def _get_unavailable_reason(
        self, plugin_data: Dict[str, Any], current_platform: str
    ) -> Optional[str]:
        if plugin_data.get("reason"):
            return plugin_data["reason"]
        supported = plugin_data.get("supported_platforms", [])
        if (
            supported
            and current_platform not in supported
            and "any-any" not in supported
        ):
            return f"Not available for {current_platform}. Supported: {', '.join(supported)}"
        return None

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Token {self.client.api_key}",
            "Content-Type": "application/json",
        }
