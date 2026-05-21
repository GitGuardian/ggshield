"""
Plugin API client - fetches available plugins from GitGuardian API.
"""

import logging
import re
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Generator, Iterator, List, Optional, Tuple
from urllib.parse import ParseResult, urlparse

import requests
from pygitguardian import GGClient

from ggshield.core.plugin.http_security import (
    assert_all_https,
    is_insecure_loopback_allowed,
    is_loopback,
)
from ggshield.core.plugin.platform import PlatformInfo, get_platform_info
from ggshield.core.plugin.wheel_utils import InvalidWheelError, sanitize_wheel_filename


logger = logging.getLogger(__name__)


HTTP_TIMEOUT_SECONDS = 30
MAX_WHEEL_SIZE_BYTES = 256 * 1024 * 1024
MAX_BUNDLE_SIZE_BYTES = 1 * 1024 * 1024


def _iter_with_size_cap(
    chunks: Iterator[bytes], max_bytes: int
) -> Generator[bytes, None, None]:
    """Yield chunks from ``chunks`` until ``max_bytes`` is exceeded."""
    written = 0
    for chunk in chunks:
        written += len(chunk)
        if written > max_bytes:
            raise PluginAPIError(
                f"Response body exceeded maximum size of {max_bytes} bytes"
            )
        yield chunk


def _parse_content_length(response: "requests.Response", *, what: str) -> int:
    """Parse ``Content-Length`` and surface malformed values as PluginAPIError.

    ``int(response.headers.get("Content-Length", 0))`` raises a raw
    ``TypeError``/``ValueError`` on a malformed header — those don't match
    the ``except requests.RequestException`` arms in the download methods
    and leak past the typed-error contract that callers depend on.
    """
    # Missing header defaults to "0" and passes the size cap silently,
    # because the streaming reader (``_iter_with_size_cap``) enforces the
    # real bound while bytes flow in. Do not "harden" this default to
    # raise — well-behaved upstreams that omit the header on small
    # responses would then fail for no reason.
    raw = response.headers.get("Content-Length", "0")
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise PluginAPIError(
            f"Malformed Content-Length header for {what}: {raw!r}"
        ) from exc


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _origin(parsed: ParseResult) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """Normalise a parsed URL to a comparable (scheme, host, port) triple.

    ``urlparse`` reports an implicit port as ``None`` and an explicit
    default port (``:443`` for https, ``:80`` for http) as the integer
    — so ``https://api.example.com`` and ``https://api.example.com:443``
    have different ``.port`` values even though the origins are
    semantically identical. Without normalisation, the same-origin
    check in ``download_signature_bundle`` rejects bundles whose URL
    came back from the backend with an explicit default port (or vice
    versa from a config edit).
    """
    port = parsed.port
    if port is None:
        port = _DEFAULT_PORTS.get(parsed.scheme)
    return (parsed.scheme, parsed.hostname, port)


def _assert_base_url_https(base_url: str) -> None:
    """Refuse to send authenticated traffic to an http:// base URL.

    The instance URL is normally validated by ``validate_instance_url`` at
    ``auth login`` time, which already rejects non-HTTPS schemes outside
    of loopback. This guard catches the residual cases — a manually
    edited config or a non-loopback http base that slipped through — so
    the API token can't be sent in cleartext before the response-side
    redirect check has anything to inspect.

    The same ``GITGUARDIAN_ALLOW_INSECURE_LOOPBACK=1`` bypass used by
    ``assert_all_https`` applies here, so local dev against
    ``http://localhost:3000`` keeps working.
    """
    if base_url.startswith("https://"):
        return
    if is_insecure_loopback_allowed() and is_loopback(base_url):
        return
    raise PluginAPIError(
        f"Refusing to send authenticated request to non-HTTPS base URL {base_url!r}"
    )


class PluginSourceType(Enum):
    """Types of plugin sources."""

    PLATFORM = "platform"
    LOCAL_FILE = "local_file"
    URL = "url"
    GITHUB_RELEASE = "github_release"
    GITHUB_ARTIFACT = "github_artifact"
    # Legacy alias kept so attribute-access uses (``PluginSourceType.GITGUARDIAN_API``)
    # in older code paths and tests still resolve to the same enum member as
    # ``PLATFORM``. Pairs with ``_missing_`` below for value-based lookup.
    GITGUARDIAN_API = "platform"

    @classmethod
    def _missing_(cls, value: object) -> Optional["PluginSourceType"]:
        """Accept legacy manifest value written by the PoC (< v1.50)."""
        if value == "gitguardian_api":
            return cls.PLATFORM
        return None


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
    reason: Optional[str] = None


@dataclass
class PluginCatalog:
    """Catalog of available plugins for the account."""

    plugins: List[PluginInfo]


@dataclass
class PluginDownloadInfo:
    """Metadata about a plugin wheel received from the platform download endpoint."""

    filename: str  # from Content-Disposition header
    sha256: str  # from X-Plugin-SHA256 header
    version: str  # from X-Plugin-Version header
    size_bytes: int  # from Content-Length header
    # Absolute URL of the sigstore bundle, from the X-Plugin-Signature-URL
    # response header. None when the platform has no bundle for this
    # artifact — STRICT verification then fails fast (as it should).
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


class PluginsNotEnabledError(Exception):
    """Plugin system is not enabled on this workspace (feature-flag OFF)."""

    pass


def _extract_server_detail(response: "requests.Response") -> Optional[str]:
    """Return the server's ``detail`` field when available, else None.

    Falls back to None on empty bodies, non-JSON responses, or JSON
    shapes without a ``detail`` field — so callers can use their own
    default message in those cases.
    """
    try:
        body = response.json()
    except (ValueError, requests.RequestException):
        return None
    if isinstance(body, dict):
        detail = body.get("detail")
        if isinstance(detail, str) and detail:
            return detail
    return None


class PluginAPIClient:
    """Client for GitGuardian plugin API."""

    API_VERSION = "v1"

    def __init__(self, client: GGClient):
        self.client = client
        self.base_url = client.base_uri.rstrip("/")

    def get_available_plugins(self) -> PluginCatalog:
        """Fetch available plugins for the authenticated account."""
        _assert_base_url_https(self.base_url)
        platform_info = get_platform_info()

        try:
            response = self.client.session.get(
                f"{self.base_url}/{self.API_VERSION}/endpoints/plugins",
                params={
                    "platform": platform_info.os,
                    "arch": platform_info.arch,
                },
                timeout=HTTP_TIMEOUT_SECONDS,
            )
            assert_all_https(response, exc_factory=PluginAPIError)
            if response.status_code == 404:
                raise PluginsNotEnabledError()
            response.raise_for_status()
        except requests.RequestException as e:
            raise PluginAPIError(f"Failed to fetch plugins: {e}") from e

        # Treat any structural mismatch (missing `reference`, non-list body,
        # non-JSON payload) as a `PluginAPIError`. The bare `p["reference"]`
        # would otherwise raise `KeyError` straight to the user — the
        # `except RequestException` above doesn't catch it.
        try:
            plugins_data = response.json()
            plugins = [
                PluginInfo(
                    name=p["reference"],
                    display_name=p.get("display_name", p["reference"]),
                    description=p.get("description", ""),
                    available=p.get("available", False),
                    latest_version=(
                        p["releases"][0]["version"] if p.get("releases") else None
                    ),
                    reason=p.get("reason"),
                )
                for p in plugins_data
            ]
        except (KeyError, TypeError, ValueError) as e:
            raise PluginAPIError(f"Malformed plugin catalog response: {e}") from e

        return PluginCatalog(plugins=plugins)

    @contextmanager
    def download_plugin(
        self,
        reference: str,
        platform_info: Optional[PlatformInfo] = None,
        version: Optional[str] = None,
    ) -> Generator[Tuple[PluginDownloadInfo, Iterator[bytes]], None, None]:
        """Stream a plugin wheel from the platform.

        Usage::

            with client.download_plugin("tokenscanner") as (info, chunks):
                downloader.download_and_install(info, chunks, "tokenscanner")
        """
        resolved = platform_info if platform_info is not None else get_platform_info()
        params: Dict[str, str] = {
            "platform": resolved.os,
            "arch": resolved.arch,
            "python_abi": resolved.python_abi,
        }
        if version:
            params["version"] = version

        _assert_base_url_https(self.base_url)
        response = None
        try:
            response = self.client.session.get(
                f"{self.base_url}/{self.API_VERSION}/endpoints/plugins/{reference}/download",
                params=params,
                stream=True,
                timeout=HTTP_TIMEOUT_SECONDS,
            )
            assert_all_https(response, exc_factory=PluginAPIError)
            if response.status_code in (403, 404):
                detail = _extract_server_detail(response)
                if not detail and response.status_code == 404:
                    detail = "Plugin or version not found"
                raise PluginNotAvailableError(reference, detail)
            response.raise_for_status()

            content_disposition = response.headers.get("Content-Disposition", "")
            match = re.search(r'filename="([^"]+)"', content_disposition)
            raw_filename = match.group(1) if match else f"{reference}.whl"
            try:
                filename = sanitize_wheel_filename(raw_filename)
            except InvalidWheelError as exc:
                raise PluginAPIError(str(exc)) from exc

            sha256 = response.headers.get("X-Plugin-SHA256")
            if not sha256:
                raise PluginAPIError(
                    f"Server response missing X-Plugin-SHA256 header for {reference}"
                )
            resolved_version = response.headers.get("X-Plugin-Version")
            if not resolved_version:
                raise PluginAPIError(
                    f"Server response missing X-Plugin-Version header for {reference}"
                )

            size_bytes = _parse_content_length(response, what="plugin wheel")
            if size_bytes > MAX_WHEEL_SIZE_BYTES:
                raise PluginAPIError(
                    f"Plugin wheel size {size_bytes} exceeds maximum "
                    f"of {MAX_WHEEL_SIZE_BYTES} bytes"
                )

            info = PluginDownloadInfo(
                filename=filename,
                sha256=sha256,
                version=resolved_version,
                size_bytes=size_bytes,
                signature_url=response.headers.get("X-Plugin-Signature-URL") or None,
            )
            yield info, _iter_with_size_cap(
                response.iter_content(chunk_size=65536), MAX_WHEEL_SIZE_BYTES
            )
        except requests.RequestException as e:
            raise PluginAPIError(f"Failed to download plugin: {e}") from e
        finally:
            if response is not None:
                response.close()

    def download_signature_bundle(self, signature_url: str) -> bytes:
        """Fetch a sigstore bundle using the authenticated session.

        The platform's ``X-Plugin-Signature-URL`` header points at our own
        ``/download/signature`` proxy (the upstream mirror URL is kept
        server-side), and that proxy requires the same Token auth as
        ``/download`` — hence using ``self.client.session`` rather than a
        bare ``requests.get``. We require the URL to share the platform's
        origin so a compromised or misconfigured backend can't coerce us
        into sending our Token to a third-party host.
        """
        _assert_base_url_https(self.base_url)
        base = urlparse(self.base_url)
        target = urlparse(signature_url)
        if _origin(target) != _origin(base):
            raise PluginAPIError(
                f"Refusing to fetch signature bundle from foreign origin "
                f"{target.scheme}://{target.hostname}"
            )

        try:
            with self.client.session.get(
                signature_url, timeout=HTTP_TIMEOUT_SECONDS, stream=True
            ) as response:
                assert_all_https(response, exc_factory=PluginAPIError)
                response.raise_for_status()

                size_bytes = _parse_content_length(response, what="signature bundle")
                if size_bytes > MAX_BUNDLE_SIZE_BYTES:
                    raise PluginAPIError(
                        f"Signature bundle size {size_bytes} exceeds maximum "
                        f"of {MAX_BUNDLE_SIZE_BYTES} bytes"
                    )

                buffer = bytearray()
                for chunk in _iter_with_size_cap(
                    response.iter_content(chunk_size=65536), MAX_BUNDLE_SIZE_BYTES
                ):
                    buffer.extend(chunk)
                return bytes(buffer)
        except requests.RequestException as e:
            raise PluginAPIError(
                f"Failed to download signature bundle from {signature_url}: {e}"
            ) from e

    def report_installation(
        self, reference: str, version: str, platform: str, arch: str
    ) -> None:
        """Report a successful plugin installation for analytics (best-effort).

        Never raises — a failure here must not fail the install. The
        explicit ``timeout`` matters because ``update.py`` historically
        called this between the wheel install and the config save, so a
        stalled ``/installed`` endpoint would leave the wheel on disk
        with the version still pointing at the previous release. The
        timeout (and the ``Exception`` catch below) keeps the call from
        blocking the user's terminal even when the backend is degraded.
        """
        try:
            # The pre-flight HTTPS check, the network call itself, and the
            # response-side redirect check all live inside the broad catch
            # below. The bare ``except Exception`` is load-bearing for the
            # "never raises" contract; ``exc_info=True`` preserves the
            # underlying cause (PluginAPIError from base-URL guard, requests
            # error from the network, etc.) in the log so it's still
            # diagnosable when someone reports a missing analytics record.
            _assert_base_url_https(self.base_url)
            response = self.client.session.post(
                f"{self.base_url}/{self.API_VERSION}/endpoints/plugins/{reference}/installed",
                json={"version": version, "platform": platform, "arch": arch},
                timeout=HTTP_TIMEOUT_SECONDS,
            )
            assert_all_https(response, exc_factory=PluginAPIError)
            response.raise_for_status()
        except Exception:
            logger.warning(
                "Failed to report plugin installation for %s v%s",
                reference,
                version,
                exc_info=True,
            )
