"""Tests for plugin API client."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from ggshield.core.plugin.client import (
    PluginAPIClient,
    PluginAPIError,
    PluginCatalog,
    PluginDownloadInfo,
    PluginInfo,
    PluginNotAvailableError,
)
from ggshield.core.plugin.platform import PlatformInfo


class TestPluginInfo:
    """Tests for PluginInfo dataclass."""

    def test_is_platform_supported_no_restrictions(self) -> None:
        """Test platform support with no restrictions."""
        info = PluginInfo(
            name="test",
            display_name="Test",
            description="Test plugin",
            available=True,
            latest_version="1.0.0",
            supported_platforms=[],
        )
        assert info.is_platform_supported("linux", "x86_64") is True
        assert info.is_platform_supported("macosx", "arm64") is True

    def test_is_platform_supported_exact_match(self) -> None:
        """Test platform support with exact match."""
        info = PluginInfo(
            name="test",
            display_name="Test",
            description="Test plugin",
            available=True,
            latest_version="1.0.0",
            supported_platforms=["linux-x86_64", "macosx-arm64"],
        )
        assert info.is_platform_supported("linux", "x86_64") is True
        assert info.is_platform_supported("macosx", "arm64") is True
        assert info.is_platform_supported("win", "amd64") is False

    def test_is_platform_supported_any_any(self) -> None:
        """Test platform support with any-any wildcard."""
        info = PluginInfo(
            name="test",
            display_name="Test",
            description="Test plugin",
            available=True,
            latest_version="1.0.0",
            supported_platforms=["any-any"],
        )
        assert info.is_platform_supported("linux", "x86_64") is True
        assert info.is_platform_supported("win", "amd64") is True


class TestPluginNotAvailableError:
    """Tests for PluginNotAvailableError."""

    def test_error_without_reason(self) -> None:
        """Test error message without reason."""
        error = PluginNotAvailableError("testplugin")
        assert error.plugin_name == "testplugin"
        assert error.reason is None
        assert str(error) == "Plugin 'testplugin' is not available"

    def test_error_with_reason(self) -> None:
        """Test error message with reason."""
        error = PluginNotAvailableError("testplugin", "Requires enterprise plan")
        assert error.plugin_name == "testplugin"
        assert error.reason == "Requires enterprise plan"
        assert (
            str(error)
            == "Plugin 'testplugin' is not available: Requires enterprise plan"
        )


class TestPluginAPIClient:
    """Tests for PluginAPIClient."""

    @pytest.fixture
    def mock_gg_client(self) -> MagicMock:
        """Create a mock GGClient."""
        client = MagicMock()
        client.base_uri = "https://api.gitguardian.com/"
        client.api_key = "test-api-key"
        client.session = MagicMock()
        return client

    def test_init(self, mock_gg_client: MagicMock) -> None:
        """Test client initialization."""
        client = PluginAPIClient(mock_gg_client)
        assert client.base_url == "https://api.gitguardian.com"
        assert client.client == mock_gg_client

    @patch("ggshield.core.plugin.client.get_platform_info")
    def test_get_available_plugins_success(
        self, mock_platform: MagicMock, mock_gg_client: MagicMock
    ) -> None:
        """Test successful plugin list fetch."""
        mock_platform.return_value = PlatformInfo(
            os="linux", arch="x86_64", python_abi="cp311"
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "plan": "enterprise",
            "features": {"local_scanning": True},
            "plugins": [
                {
                    "name": "tokenscanner",
                    "display_name": "Token Scanner",
                    "description": "Local scanning",
                    "available": True,
                    "latest_version": "1.0.0",
                }
            ],
        }
        mock_gg_client.session.get.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)
        catalog = client.get_available_plugins()

        assert isinstance(catalog, PluginCatalog)
        assert catalog.plan == "enterprise"
        assert catalog.features == {"local_scanning": True}
        assert len(catalog.plugins) == 1
        assert catalog.plugins[0].name == "tokenscanner"

    @patch("ggshield.core.plugin.client.get_platform_info")
    def test_get_available_plugins_request_error(
        self, mock_platform: MagicMock, mock_gg_client: MagicMock
    ) -> None:
        """Test plugin list fetch with request error."""
        mock_platform.return_value = PlatformInfo(
            os="linux", arch="x86_64", python_abi="cp311"
        )

        mock_gg_client.session.get.side_effect = requests.RequestException(
            "Connection failed"
        )

        client = PluginAPIClient(mock_gg_client)

        with pytest.raises(PluginAPIError) as exc_info:
            client.get_available_plugins()

        assert "Failed to fetch plugins" in str(exc_info.value)

    @patch("ggshield.core.plugin.client.get_platform_info")
    def test_get_download_info_success(
        self, mock_platform: MagicMock, mock_gg_client: MagicMock
    ) -> None:
        """Test successful download info fetch."""
        mock_platform.return_value = PlatformInfo(
            os="linux", arch="x86_64", python_abi="cp311"
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "download_url": "https://example.com/plugin.whl",
            "filename": "plugin-1.0.0.whl",
            "sha256": "abc123",
            "version": "1.0.0",
            "expires_at": "2025-01-01T00:00:00Z",
        }
        mock_gg_client.session.get.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)
        info = client.get_download_info("testplugin")

        assert isinstance(info, PluginDownloadInfo)
        assert info.download_url == "https://example.com/plugin.whl"
        assert info.filename == "plugin-1.0.0.whl"
        assert info.sha256 == "abc123"
        assert info.version == "1.0.0"

    @patch("ggshield.core.plugin.client.get_platform_info")
    def test_get_download_info_with_version(
        self, mock_platform: MagicMock, mock_gg_client: MagicMock
    ) -> None:
        """Test download info fetch with specific version."""
        mock_platform.return_value = PlatformInfo(
            os="linux", arch="x86_64", python_abi="cp311"
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "download_url": "https://example.com/plugin.whl",
            "filename": "plugin-0.9.0.whl",
            "sha256": "def456",
            "version": "0.9.0",
            "expires_at": "2025-01-01T00:00:00Z",
        }
        mock_gg_client.session.get.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)
        info = client.get_download_info("testplugin", version="0.9.0")

        assert info.version == "0.9.0"
        mock_gg_client.session.get.assert_called_once()
        call_kwargs = mock_gg_client.session.get.call_args[1]
        assert call_kwargs["params"]["version"] == "0.9.0"

    @patch("ggshield.core.plugin.client.get_platform_info")
    def test_get_download_info_forbidden(
        self, mock_platform: MagicMock, mock_gg_client: MagicMock
    ) -> None:
        """Test download info with 403 response."""
        mock_platform.return_value = PlatformInfo(
            os="linux", arch="x86_64", python_abi="cp311"
        )

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_gg_client.session.get.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)

        with pytest.raises(PluginNotAvailableError) as exc_info:
            client.get_download_info("testplugin")

        assert exc_info.value.plugin_name == "testplugin"

    @patch("ggshield.core.plugin.client.get_platform_info")
    def test_get_download_info_not_found(
        self, mock_platform: MagicMock, mock_gg_client: MagicMock
    ) -> None:
        """Test download info with 404 response."""
        mock_platform.return_value = PlatformInfo(
            os="linux", arch="x86_64", python_abi="cp311"
        )

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_gg_client.session.get.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)

        with pytest.raises(PluginNotAvailableError) as exc_info:
            client.get_download_info("testplugin")

        assert "not found" in exc_info.value.reason.lower()

    def test_is_plugin_available_explicit_false(
        self, mock_gg_client: MagicMock
    ) -> None:
        """Test _is_plugin_available with explicit available=false."""
        client = PluginAPIClient(mock_gg_client)
        plugin_data = {"available": False}
        assert client._is_plugin_available(plugin_data, "linux-x86_64") is False

    def test_is_plugin_available_no_platform_restrictions(
        self, mock_gg_client: MagicMock
    ) -> None:
        """Test _is_plugin_available with no platform restrictions."""
        client = PluginAPIClient(mock_gg_client)
        plugin_data = {"available": True, "supported_platforms": []}
        assert client._is_plugin_available(plugin_data, "linux-x86_64") is True

    def test_is_plugin_available_platform_match(
        self, mock_gg_client: MagicMock
    ) -> None:
        """Test _is_plugin_available with matching platform."""
        client = PluginAPIClient(mock_gg_client)
        plugin_data = {"available": True, "supported_platforms": ["linux-x86_64"]}
        assert client._is_plugin_available(plugin_data, "linux-x86_64") is True
        assert client._is_plugin_available(plugin_data, "win-amd64") is False

    def test_is_plugin_available_any_any(self, mock_gg_client: MagicMock) -> None:
        """Test _is_plugin_available with any-any wildcard."""
        client = PluginAPIClient(mock_gg_client)
        plugin_data = {"available": True, "supported_platforms": ["any-any"]}
        assert client._is_plugin_available(plugin_data, "linux-x86_64") is True
        assert client._is_plugin_available(plugin_data, "win-amd64") is True

    def test_get_unavailable_reason_explicit(self, mock_gg_client: MagicMock) -> None:
        """Test _get_unavailable_reason with explicit reason."""
        client = PluginAPIClient(mock_gg_client)
        plugin_data = {"reason": "Requires enterprise plan"}
        assert (
            client._get_unavailable_reason(plugin_data, "linux-x86_64")
            == "Requires enterprise plan"
        )

    def test_get_unavailable_reason_platform_mismatch(
        self, mock_gg_client: MagicMock
    ) -> None:
        """Test _get_unavailable_reason with platform mismatch."""
        client = PluginAPIClient(mock_gg_client)
        plugin_data = {"supported_platforms": ["macosx-arm64"]}
        reason = client._get_unavailable_reason(plugin_data, "linux-x86_64")
        assert reason is not None
        assert "linux-x86_64" in reason
        assert "macosx-arm64" in reason

    def test_get_unavailable_reason_none(self, mock_gg_client: MagicMock) -> None:
        """Test _get_unavailable_reason returns None when available."""
        client = PluginAPIClient(mock_gg_client)
        plugin_data = {"supported_platforms": ["linux-x86_64"]}
        assert client._get_unavailable_reason(plugin_data, "linux-x86_64") is None

    def test_get_headers(self, mock_gg_client: MagicMock) -> None:
        """Test _get_headers returns correct headers."""
        client = PluginAPIClient(mock_gg_client)
        headers = client._get_headers()
        assert headers["Authorization"] == "Token test-api-key"
        assert headers["Content-Type"] == "application/json"
