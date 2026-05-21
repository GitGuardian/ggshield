"""
Plugin downloader - downloads and installs plugin wheels.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests

from ggshield.core.dirs import get_plugins_dir
from ggshield.core.plugin.client import (
    PluginDownloadInfo,
    PluginSource,
    PluginSourceType,
)
from ggshield.core.plugin.signature import (
    SignatureInfo,
    SignatureStatus,
    SignatureVerificationError,
    SignatureVerificationMode,
    verify_wheel_signature,
)
from ggshield.core.plugin.trust import PluginTrustStore
from ggshield.core.plugin.wheel_utils import WheelError, extract_wheel_metadata
from ggshield.utils.files import atomic_write_text


logger = logging.getLogger(__name__)


def get_signature_label(
    manifest: Dict[str, Any],
    *,
    trusted_unsigned: bool = False,
) -> Optional[str]:
    """Get a human-readable signature status label from a manifest."""
    sig_info = manifest.get("signature")
    if not sig_info:
        return None

    status = sig_info.get("status", "unknown")
    identity = sig_info.get("identity")

    if status == SignatureStatus.VALID.value:
        if identity:
            return f"signed ({identity})"
        return "signed"

    if trusted_unsigned:
        return "unsigned (trusted)"

    if identity:
        return f"{status} ({identity})"
    return status


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


class InsecureSourceError(DownloadError):
    """Plugin source is not secure (e.g., HTTP instead of HTTPS)."""

    pass


class GitHubArtifactError(DownloadError):
    """Error downloading GitHub artifact."""

    pass


class PluginDownloader:
    """Downloads and installs plugin wheels."""

    def __init__(self) -> None:
        self.plugins_dir = get_plugins_dir(create=True)
        self.trust_store = PluginTrustStore(plugins_dir=self.plugins_dir)

    def download_and_install(
        self,
        download_info: PluginDownloadInfo,
        plugin_name: str,
        source: Optional[PluginSource] = None,
        signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
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
                raise ChecksumMismatchError(download_info.sha256, computed_hash)

            # Remove any stale bundle sidecars for this wheel name before
            # writing the new wheel/bundle pair.
            self._remove_bundle_files(wheel_path)

            # Download signature bundle if available
            temp_path.rename(wheel_path)
            self._download_bundle(download_info, plugin_dir)

            # Verify signature
            sig_info = verify_wheel_signature(wheel_path, signature_mode)

            # Use GitGuardian API as default source if not provided
            if source is None:
                source = PluginSource(type=PluginSourceType.GITGUARDIAN_API)

            # Sync trust record before writing the manifest so a trust failure
            # cannot leave an orphaned manifest pointing at a wheel we remove
            # during cleanup.
            self._sync_trust_record(plugin_name, download_info.sha256, sig_info)
            self._write_manifest(
                plugin_dir=plugin_dir,
                plugin_name=plugin_name,
                version=download_info.version,
                wheel_filename=download_info.filename,
                sha256=download_info.sha256,
                source=source,
                signature_info=sig_info,
            )

            logger.info("Installed %s v%s", plugin_name, download_info.version)

            return wheel_path

        except requests.RequestException as e:
            self._cleanup_failed_install(wheel_path)
            raise DownloadError(f"Failed to download plugin: {e}") from e
        except SignatureVerificationError:
            self._cleanup_failed_install(wheel_path)
            raise
        except Exception:
            self._cleanup_failed_install(wheel_path)
            raise
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def install_from_wheel(
        self,
        wheel_path: Path,
        signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
    ) -> Tuple[str, str, Path]:
        """
        Install a plugin from a local wheel file.

        Args:
            wheel_path: Path to the wheel file.
            signature_mode: Signature verification mode.

        Returns:
            Tuple of (plugin_name, version, installed_wheel_path).

        Raises:
            WheelError: If the wheel file is invalid.
            DownloadError: If installation fails.
            SignatureVerificationError: In STRICT mode when signature is invalid.
        """
        # Extract metadata from wheel
        try:
            metadata = extract_wheel_metadata(wheel_path)
        except WheelError as e:
            raise DownloadError(f"Invalid wheel file: {e}") from e

        plugin_name = metadata.name
        version = metadata.version
        self._validate_plugin_name(plugin_name)

        # Create plugin directory
        plugin_dir = self.plugins_dir / plugin_name
        plugin_dir.mkdir(parents=True, exist_ok=True)

        # Copy wheel to plugin directory
        dest_wheel_path = plugin_dir / wheel_path.name
        self._remove_bundle_files(dest_wheel_path)
        shutil.copy2(wheel_path, dest_wheel_path)

        # Copy bundle if it exists alongside the wheel
        from ggshield.core.plugin.signature import get_bundle_path

        bundle_path = get_bundle_path(wheel_path)
        if bundle_path is not None:
            shutil.copy2(bundle_path, plugin_dir / bundle_path.name)

        # Verify signature
        sig_info = verify_wheel_signature(dest_wheel_path, signature_mode)

        # Compute SHA256
        sha256 = self._compute_sha256(dest_wheel_path)

        # Create source tracking
        source = PluginSource(
            type=PluginSourceType.LOCAL_FILE,
            local_path=str(wheel_path.resolve()),
            sha256=sha256,
        )

        self._sync_trust_record(plugin_name, sha256, sig_info)
        self._write_manifest(
            plugin_dir=plugin_dir,
            plugin_name=plugin_name,
            version=version,
            wheel_filename=wheel_path.name,
            sha256=sha256,
            source=source,
            signature_info=sig_info,
        )

        logger.info("Installed %s v%s from local wheel", plugin_name, version)

        return plugin_name, version, dest_wheel_path

    def download_from_url(
        self,
        url: str,
        sha256: Optional[str] = None,
        signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
    ) -> Tuple[str, str, Path]:
        """
        Download and install a plugin from a URL.

        Args:
            url: URL to download the wheel from.
            sha256: Expected SHA256 checksum (optional but recommended).
            signature_mode: Signature verification mode.

        Returns:
            Tuple of (plugin_name, version, installed_wheel_path).

        Raises:
            InsecureSourceError: If URL uses HTTP instead of HTTPS.
            ChecksumMismatchError: If checksum doesn't match.
            DownloadError: If download or installation fails.
            SignatureVerificationError: In STRICT mode when signature is invalid.
        """
        # Security check: require HTTPS
        if url.startswith("http://"):
            raise InsecureSourceError(
                "HTTP URLs are not allowed for security reasons. Use HTTPS instead."
            )

        if not url.startswith("https://"):
            raise DownloadError(f"Invalid URL scheme: {url}")

        # Download to temp file
        with tempfile.TemporaryDirectory() as temp_dir:
            # Extract filename from URL
            filename = url.split("/")[-1].split("?")[0]
            if not filename.endswith(".whl"):
                filename = "plugin.whl"

            temp_wheel_path = Path(temp_dir) / filename

            try:
                logger.info("Downloading from %s...", url)
                response = requests.get(url, stream=True)
                response.raise_for_status()

                sha256_hash = hashlib.sha256()
                with open(temp_wheel_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                        sha256_hash.update(chunk)

                computed_hash = sha256_hash.hexdigest()

                # Verify checksum if provided
                if sha256 and computed_hash.lower() != sha256.lower():
                    raise ChecksumMismatchError(sha256, computed_hash)

            except requests.RequestException as e:
                raise DownloadError(f"Failed to download from URL: {e}") from e

            # Extract metadata
            try:
                metadata = extract_wheel_metadata(temp_wheel_path)
            except WheelError as e:
                raise DownloadError(f"Downloaded file is not a valid wheel: {e}") from e

            plugin_name = metadata.name
            version = metadata.version
            self._validate_plugin_name(plugin_name)

            # Create plugin directory and copy wheel
            plugin_dir = self.plugins_dir / plugin_name
            plugin_dir.mkdir(parents=True, exist_ok=True)

            dest_wheel_path = plugin_dir / temp_wheel_path.name
            self._remove_bundle_files(dest_wheel_path)
            shutil.copy2(temp_wheel_path, dest_wheel_path)

        # Try downloading the signature bundle alongside the wheel
        self._download_url_bundle(url, dest_wheel_path)

        # Verify signature
        sig_info = verify_wheel_signature(dest_wheel_path, signature_mode)

        # Create source tracking
        source = PluginSource(
            type=PluginSourceType.URL,
            url=url,
            sha256=computed_hash,
        )

        self._sync_trust_record(plugin_name, computed_hash, sig_info)
        self._write_manifest(
            plugin_dir=plugin_dir,
            plugin_name=plugin_name,
            version=version,
            wheel_filename=dest_wheel_path.name,
            sha256=computed_hash,
            source=source,
            signature_info=sig_info,
        )

        logger.info("Installed %s v%s from URL", plugin_name, version)

        return plugin_name, version, dest_wheel_path

    def download_from_github_release(
        self,
        url: str,
        sha256: Optional[str] = None,
        signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
    ) -> Tuple[str, str, Path]:
        """
        Download and install a plugin from a GitHub release asset.

        Args:
            url: GitHub release asset URL.
            sha256: Expected SHA256 checksum (optional).
            signature_mode: Signature verification mode.

        Returns:
            Tuple of (plugin_name, version, installed_wheel_path).
        """
        # Extract repo info from URL for source tracking
        github_repo = self._extract_github_repo(url)

        # Download using standard URL method
        plugin_name, version, wheel_path = self.download_from_url(
            url, sha256, signature_mode=signature_mode
        )

        # Update source to track GitHub release
        manifest_path = self.plugins_dir / plugin_name / "manifest.json"
        manifest = json.loads(manifest_path.read_text())

        source = PluginSource(
            type=PluginSourceType.GITHUB_RELEASE,
            url=url,
            github_repo=github_repo,
            sha256=manifest.get("sha256"),
        )
        manifest["source"] = source.to_dict()
        manifest_path.write_text(json.dumps(manifest, indent=2))

        return plugin_name, version, wheel_path

    def download_from_github_artifact(
        self,
        url: str,
        signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
    ) -> Tuple[str, str, Path]:
        """
        Download and install a plugin from a GitHub Actions artifact.

        GitHub artifacts are ZIP files containing wheel(s). This method:
        1. Downloads the artifact ZIP
        2. Extracts the wheel file
        3. Installs the wheel

        Args:
            url: GitHub artifact URL (browser URL or API URL).
            signature_mode: Signature verification mode.

        Returns:
            Tuple of (plugin_name, version, installed_wheel_path).

        Raises:
            GitHubArtifactError: If artifact cannot be downloaded or processed.
            DownloadError: If installation fails.
            SignatureVerificationError: In STRICT mode when signature is invalid.
        """
        # Parse artifact URL to get API endpoint
        artifact_info = self._parse_github_artifact_url(url)
        if not artifact_info:
            raise GitHubArtifactError(f"Invalid GitHub artifact URL: {url}")

        owner, repo, artifact_id = artifact_info

        # Get GitHub token from environment
        github_token = os.environ.get("GITHUB_TOKEN")
        if not github_token:
            # Try gh CLI as fallback
            github_token = self._get_gh_token()

        if not github_token:
            raise GitHubArtifactError(
                "GitHub authentication required. Set GITHUB_TOKEN environment variable "
                "or install and authenticate with GitHub CLI (gh auth login)."
            )

        # Download artifact ZIP
        api_url = f"https://api.github.com/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip"

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = Path(temp_dir)
            artifact_zip_path = temp_dir_path / "artifact.zip"

            try:
                logger.info("Downloading GitHub artifact...")
                response = requests.get(
                    api_url,
                    headers={
                        "Authorization": f"Bearer {github_token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                    stream=True,
                )
                response.raise_for_status()

                with open(artifact_zip_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

            except requests.RequestException as e:
                raise GitHubArtifactError(f"Failed to download artifact: {e}") from e

            # Extract ZIP and find wheel
            extract_dir = temp_dir_path / "extracted"

            try:
                from ggshield.utils.archive import safe_unpack

                safe_unpack(artifact_zip_path, extract_dir)
            except Exception as e:
                raise GitHubArtifactError(f"Failed to extract artifact: {e}") from e

            # Find wheel file in extracted contents
            wheel_files = list(extract_dir.glob("**/*.whl"))
            if not wheel_files:
                raise GitHubArtifactError("No wheel file found in artifact")

            if len(wheel_files) > 1:
                logger.warning(
                    "Multiple wheel files found in artifact, using first: %s",
                    wheel_files[0].name,
                )

            temp_wheel_path = wheel_files[0]

            # Extract metadata
            try:
                metadata = extract_wheel_metadata(temp_wheel_path)
            except WheelError as e:
                raise DownloadError(f"Invalid wheel in artifact: {e}") from e

            plugin_name = metadata.name
            version = metadata.version
            self._validate_plugin_name(plugin_name)

            # Create plugin directory and copy wheel
            plugin_dir = self.plugins_dir / plugin_name
            plugin_dir.mkdir(parents=True, exist_ok=True)

            dest_wheel_path = plugin_dir / temp_wheel_path.name
            self._remove_bundle_files(dest_wheel_path)
            shutil.copy2(temp_wheel_path, dest_wheel_path)

            # Copy bundle alongside the wheel if present in the artifact
            for ext in (".sigstore", ".sigstore.json"):
                bundle_src = temp_wheel_path.parent / (temp_wheel_path.name + ext)
                if bundle_src.exists():
                    shutil.copy2(bundle_src, plugin_dir / bundle_src.name)
                    break

            # Compute SHA256
            sha256 = self._compute_sha256(dest_wheel_path)

        # Verify signature
        sig_info = verify_wheel_signature(dest_wheel_path, signature_mode)

        # Create source tracking
        source = PluginSource(
            type=PluginSourceType.GITHUB_ARTIFACT,
            url=url,
            github_repo=f"{owner}/{repo}",
            sha256=sha256,
        )

        self._sync_trust_record(plugin_name, sha256, sig_info)
        self._write_manifest(
            plugin_dir=plugin_dir,
            plugin_name=plugin_name,
            version=version,
            wheel_filename=dest_wheel_path.name,
            sha256=sha256,
            source=source,
            signature_info=sig_info,
        )

        logger.info("Installed %s v%s from GitHub artifact", plugin_name, version)

        return plugin_name, version, dest_wheel_path

    def uninstall(self, plugin_name: str) -> bool:
        """Uninstall a plugin (by package name or entry point name)."""
        if not self._is_valid_plugin_name(plugin_name):
            logger.warning("Invalid plugin name: %s", plugin_name)
            return False

        plugin_dir = self._resolve_plugin_dir(plugin_name)
        if plugin_dir is None:
            return False

        self.trust_store.revoke_plugin(plugin_dir.name)
        shutil.rmtree(plugin_dir)

        logger.info("Uninstalled plugin: %s", plugin_name)
        return True

    def get_installed_version(self, plugin_name: str) -> Optional[str]:
        """Get the installed version of a plugin (by package name or entry point name)."""
        manifest = self.get_manifest(plugin_name)
        if not manifest:
            return None
        return manifest.get("version")

    def is_installed(self, plugin_name: str) -> bool:
        """Check if a plugin is installed (by package name or entry point name)."""
        return self.get_installed_version(plugin_name) is not None

    def _resolve_plugin_dir(self, plugin_name: str) -> Optional[Path]:
        """Resolve a plugin directory from a package or entry point name."""
        plugin_dir = self.plugins_dir / plugin_name
        if plugin_dir.exists():
            return plugin_dir
        return self._find_plugin_dir_by_entry_point(plugin_name)

    def _get_manifest_path(self, plugin_name: str) -> Optional[Path]:
        """Return the manifest path for a plugin installed by package or entry point."""
        if not self._is_valid_plugin_name(plugin_name):
            logger.warning("Invalid plugin name: %s", plugin_name)
            return None

        plugin_dir = self._resolve_plugin_dir(plugin_name)
        if plugin_dir is None:
            return None

        manifest_path = plugin_dir / "manifest.json"
        if not manifest_path.exists():
            return None
        return manifest_path

    def _find_plugin_dir_by_entry_point(self, entry_point_name: str) -> Optional[Path]:
        """Find a plugin directory by its entry point name."""
        if not self.plugins_dir.exists():
            return None

        for plugin_dir in self.plugins_dir.iterdir():
            if not plugin_dir.is_dir():
                continue

            manifest_path = plugin_dir / "manifest.json"
            if not manifest_path.exists():
                continue

            try:
                manifest = json.loads(manifest_path.read_text())
                wheel_filename = manifest.get("wheel_filename", "")
                wheel_path = plugin_dir / wheel_filename

                if wheel_path.exists():
                    # Read entry point name from wheel
                    ep_name = self._read_entry_point_name_from_wheel(wheel_path)
                    if ep_name == entry_point_name:
                        return plugin_dir
            except (json.JSONDecodeError, KeyError):
                continue

        return None

    def _read_entry_point_name_from_wheel(self, wheel_path: Path) -> Optional[str]:
        """Read the entry point name from a wheel file."""
        from ggshield.core.plugin.loader import read_entry_point_from_wheel

        result = read_entry_point_from_wheel(wheel_path)
        return result[0] if result else None

    def get_wheel_path(self, plugin_name: str) -> Optional[Path]:
        """Get the path to an installed plugin's wheel file."""
        manifest_path = self._get_manifest_path(plugin_name)
        if manifest_path is None:
            return None

        try:
            manifest = json.loads(manifest_path.read_text())
            wheel_filename = manifest.get("wheel_filename")
            if wheel_filename:
                wheel_path = manifest_path.parent / wheel_filename
                if wheel_path.exists():
                    return wheel_path
        except (json.JSONDecodeError, KeyError):
            pass

        return None

    def get_manifest(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get the full manifest for an installed plugin."""
        manifest_path = self._get_manifest_path(plugin_name)
        if manifest_path is None:
            return None

        try:
            return json.loads(manifest_path.read_text())
        except json.JSONDecodeError:
            return None

    def get_installed_signature_label(self, plugin_name: str) -> Optional[str]:
        """Return the display label for an installed plugin's signature state."""
        manifest = self.get_manifest(plugin_name)
        if not manifest:
            return None

        trusted_unsigned = False
        wheel_path = self.get_wheel_path(plugin_name)
        if wheel_path is not None:
            trusted_unsigned = self.trust_store.is_trusted(
                wheel_path.parent.name,
                self._compute_sha256(wheel_path),
            )

        return get_signature_label(manifest, trusted_unsigned=trusted_unsigned)

    def get_plugin_source(self, plugin_name: str) -> Optional[PluginSource]:
        """Get the source information for an installed plugin."""
        manifest = self.get_manifest(plugin_name)
        if not manifest:
            return None

        source_data = manifest.get("source")
        if not source_data:
            # Legacy manifest without source tracking - assume GitGuardian API
            return PluginSource(type=PluginSourceType.GITGUARDIAN_API)

        try:
            return PluginSource.from_dict(source_data)
        except (KeyError, ValueError):
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

    def _write_manifest(
        self,
        plugin_dir: Path,
        plugin_name: str,
        version: str,
        wheel_filename: str,
        sha256: str,
        source: PluginSource,
        signature_info: Optional[SignatureInfo] = None,
    ) -> None:
        """Write the plugin manifest file."""
        manifest: Dict[str, Any] = {
            "plugin_name": plugin_name,
            "version": version,
            "wheel_filename": wheel_filename,
            "sha256": sha256,
            "source": source.to_dict(),
            "installed_at": datetime.now(timezone.utc).isoformat(),
        }
        if signature_info is not None:
            sig_data: Dict[str, Any] = {"status": signature_info.status.value}
            if signature_info.identity:
                sig_data["identity"] = signature_info.identity
            if signature_info.message:
                sig_data["message"] = signature_info.message
            manifest["signature"] = sig_data

        manifest_path = plugin_dir / "manifest.json"
        atomic_write_text(manifest_path, json.dumps(manifest, indent=2))

    def _sync_trust_record(
        self,
        plugin_name: str,
        sha256: str,
        signature_info: SignatureInfo,
    ) -> None:
        """Persist or revoke trust for a plugin based on install-time verification.

        When a plugin is installed with a VALID signature we remove any stale
        trust exception (from a previous unsigned install). Otherwise we record
        the new hash — ``trust_plugin`` overwrites the existing entry so we do
        not need to revoke first.
        """
        if signature_info.status == SignatureStatus.VALID:
            self.trust_store.revoke_plugin(plugin_name)
            return

        self.trust_store.trust_plugin(
            plugin_name,
            sha256,
            signature_info.status.value,
        )

    def _download_bundle(
        self,
        download_info: PluginDownloadInfo,
        plugin_dir: Path,
    ) -> Optional[Path]:
        """Download the sigstore bundle for a wheel if a signature URL is available."""
        if not download_info.signature_url:
            return None

        bundle_filename = download_info.filename + ".sigstore"
        bundle_path = plugin_dir / bundle_filename

        try:
            logger.info("Downloading signature bundle...")
            response = requests.get(
                download_info.signature_url, stream=True, timeout=30
            )
            response.raise_for_status()

            try:
                with open(bundle_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
            except BaseException:
                # Remove any partial bundle left behind by a mid-stream error.
                if bundle_path.exists():
                    bundle_path.unlink()
                raise

            return bundle_path
        except requests.RequestException as e:
            logger.warning("Failed to download signature bundle: %s", e)
            return None

    def _download_url_bundle(
        self, wheel_url: str, dest_wheel_path: Path
    ) -> Optional[Path]:
        """Try downloading a sigstore bundle from URL conventions.

        Tries {wheel_url}.sigstore first, then {wheel_url}.sigstore.json.
        """
        for ext in (".sigstore", ".sigstore.json"):
            bundle_url = wheel_url + ext
            bundle_path = dest_wheel_path.parent / (dest_wheel_path.name + ext)
            try:
                response = requests.get(bundle_url, stream=True, timeout=30)
                response.raise_for_status()

                try:
                    with open(bundle_path, "wb") as f:
                        for chunk in response.iter_content(chunk_size=8192):
                            f.write(chunk)
                except BaseException:
                    if bundle_path.exists():
                        bundle_path.unlink()
                    raise

                logger.info("Downloaded signature bundle from %s", bundle_url)
                return bundle_path
            except requests.RequestException:
                continue

        logger.debug("No signature bundle found at URL conventions for %s", wheel_url)
        return None

    def _remove_bundle_files(self, wheel_path: Path) -> None:
        """Remove any bundle sidecars associated with a wheel path."""
        for ext in (".sigstore", ".sigstore.json"):
            bundle = wheel_path.parent / (wheel_path.name + ext)
            if bundle.exists():
                bundle.unlink()

    def _cleanup_failed_install(self, wheel_path: Path) -> None:
        """Remove wheel and bundle files after a failed install."""
        if wheel_path.exists():
            wheel_path.unlink()

        self._remove_bundle_files(wheel_path)

    def _compute_sha256(self, file_path: Path) -> str:
        """Compute SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def _extract_github_repo(self, url: str) -> Optional[str]:
        """Extract owner/repo from a GitHub URL."""
        # Pattern: github.com/{owner}/{repo}/...
        match = re.match(r"https://github\.com/([^/]+)/([^/]+)", url)
        if match:
            return f"{match.group(1)}/{match.group(2)}"
        return None

    def _parse_github_artifact_url(self, url: str) -> Optional[Tuple[str, str, str]]:
        """
        Parse GitHub artifact URL to extract owner, repo, and artifact ID.

        Supports URLs like:
        - https://github.com/{owner}/{repo}/actions/runs/{run_id}/artifacts/{artifact_id}
        """
        pattern = (
            r"https://github\.com/([^/]+)/([^/]+)/actions/runs/\d+/artifacts/(\d+)"
        )
        match = re.match(pattern, url)
        if match:
            return match.group(1), match.group(2), match.group(3)
        return None

    def _get_gh_token(self) -> Optional[str]:
        """Try to get GitHub token from gh CLI."""
        import subprocess

        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return None
