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
from typing import Any, Dict, Iterator, Optional, Tuple

import requests

from ggshield.core.dirs import get_cache_dir, get_plugins_dir
from ggshield.core.plugin.client import (
    PluginDownloadInfo,
    PluginSource,
    PluginSourceType,
)
from ggshield.core.plugin.http_security import assert_all_https
from ggshield.core.plugin.signature import (
    SignatureInfo,
    SignatureStatus,
    SignatureVerificationMode,
    verify_wheel_signature,
)
from ggshield.core.plugin.trust import PluginTrustStore, compute_file_sha256
from ggshield.core.plugin.wheel_utils import (
    InvalidWheelError,
    WheelError,
    extract_wheel_metadata,
    sanitize_wheel_filename,
)


logger = logging.getLogger(__name__)


def _wheel_distribution_name(filename: str) -> str:
    """Return the PEP 503-normalised distribution name from a wheel filename.

    PEP 427 wheel filenames are
    ``{distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl``.
    The distribution segment uses ``_`` in place of ``-`` from the
    canonical name, so the inverse normalisation
    (``lower()`` + ``_ -> -``) recovers the PEP 503 form. We only need
    the distribution segment, so a simple split on ``-`` is enough.
    """
    if not filename.endswith(".whl"):
        raise DownloadError(f"Not a wheel filename: {filename!r}")
    stem = filename.removesuffix(".whl")
    parts = stem.split("-", 1)
    if len(parts) < 2 or not parts[0]:
        raise DownloadError(f"Invalid wheel filename: {filename!r}")
    return parts[0].lower().replace("_", "-")


HTTP_TIMEOUT_SECONDS = 30
MAX_WHEEL_SIZE_BYTES = 256 * 1024 * 1024
MAX_BUNDLE_SIZE_BYTES = 1 * 1024 * 1024


def _stream_to_file(
    response: "requests.Response",
    dest: Path,
    max_bytes: int,
    *,
    hash_bytes: bool = False,
) -> Optional[str]:
    """Stream an HTTP response body to ``dest`` with a hard size cap.

    When ``hash_bytes`` is True, also computes SHA256 in a single pass and
    returns the hex digest; otherwise returns None. Raises ``DownloadError``
    if the response body exceeds ``max_bytes``; the partial file is then
    removed before the exception propagates.
    """
    sha256_hash = hashlib.sha256() if hash_bytes else None
    written = 0
    try:
        with open(dest, "wb") as f:
            for chunk in response.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                written += len(chunk)
                if written > max_bytes:
                    raise DownloadError(
                        f"Response body exceeded maximum size of {max_bytes} bytes"
                    )
                f.write(chunk)
                if sha256_hash is not None:
                    sha256_hash.update(chunk)
    except BaseException:
        if dest.exists():
            dest.unlink()
        raise
    return sha256_hash.hexdigest() if sha256_hash is not None else None


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
        chunks: Iterator[bytes],
        plugin_name: str,
        source: Optional[PluginSource] = None,
        signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
        bundle_bytes: Optional[bytes] = None,
    ) -> Path:
        """Install a plugin wheel from a byte stream.

        The on-disk plugin directory is named after the wheel's
        distribution name (PEP 427 → PEP 503), same as
        :meth:`install_from_wheel`. ``plugin_name`` is the catalog
        reference used for the API call and stored in the manifest;
        when it differs from the wheel's distribution name (e.g. the
        catalog references ``machine_scan`` while the wheel ships
        as ``satori-python``), a subsequent local-wheel install of
        the same package overwrites this install in place rather than
        creating a side-by-side directory.

        Args:
            download_info: Filename, SHA256, version from the platform response headers.
            chunks: Iterator of raw bytes (from streaming HTTP response or test fixture).
            plugin_name: Catalog reference used for the API call and stored in the manifest.
            source: Manifest source record. Defaults to PluginSourceType.PLATFORM.
            signature_mode: Sigstore verification mode.
            bundle_bytes: Optional sigstore bundle bytes fetched by the
                caller (typically via ``PluginAPIClient.download_signature_bundle``
                using the ``X-Plugin-Signature-URL`` header). Written next
                to the wheel before verification runs, so STRICT mode
                succeeds when the platform exposes a signature.

        Returns:
            Path to the installed wheel file. The parent directory's name
            is the wheel's distribution name and matches what
            :meth:`install_from_wheel` would use for the same wheel.

        Raises:
            ChecksumMismatchError: SHA256 of received bytes does not match download_info.sha256.
            DownloadError: File system error during installation.
            SignatureVerificationError: In STRICT mode when signature is invalid.
        """
        self._validate_plugin_name(plugin_name)

        # The on-disk plugin directory comes from the wheel's
        # distribution name (PEP 427 → PEP 503), not from the catalog
        # reference, so the catalog install converges with a previous
        # ``install_from_wheel`` of the same wheel rather than creating
        # a side-by-side directory. ``download_info.filename`` was
        # validated by the API client (``sanitize_wheel_filename``) and
        # came from the trusted catalog response.
        install_dir_name = _wheel_distribution_name(download_info.filename)
        self._validate_plugin_name(install_dir_name)

        plugin_dir = self.plugins_dir / install_dir_name
        plugin_dir.mkdir(parents=True, exist_ok=True)
        wheel_path = plugin_dir / download_info.filename
        temp_path = plugin_dir / f"{download_info.filename}.tmp"

        # Drop the new bundle next to the TEMP wheel so verification can
        # happen before we touch the previous install. ``temp_bundle_path``
        # is cleaned up alongside ``temp_path`` in the finally block.
        temp_bundle_path = (
            temp_path.parent / (temp_path.name + ".sigstore")
            if bundle_bytes is not None
            else None
        )

        try:
            logger.info("Installing %s...", download_info.filename)
            sha256_hash = hashlib.sha256()
            with open(temp_path, "wb") as f:
                for chunk in chunks:
                    f.write(chunk)
                    sha256_hash.update(chunk)

            computed_hash = sha256_hash.hexdigest()
            if computed_hash.lower() != download_info.sha256.lower():
                raise ChecksumMismatchError(download_info.sha256, computed_hash)

            if temp_bundle_path is not None:
                temp_bundle_path.write_bytes(bundle_bytes)  # type: ignore[arg-type]

            # Verify on the temp wheel BEFORE we touch the existing
            # install. ``verify_wheel_signature`` looks for the bundle
            # next to the wheel; we placed it next to ``temp_path`` for
            # exactly that. A STRICT failure here leaves the previous
            # working wheel + manifest intact.
            sig_info = verify_wheel_signature(temp_path, signature_mode)

            # Verification passed: now safe to swap. Remove the stale
            # bundle sidecars, move the new wheel into place, then drop
            # the fresh bundle next to it.
            self._remove_bundle_files(wheel_path)
            temp_path.replace(wheel_path)
            if temp_bundle_path is not None:
                final_bundle_path = wheel_path.parent / (wheel_path.name + ".sigstore")
                temp_bundle_path.replace(final_bundle_path)

            if source is None:
                source = PluginSource(type=PluginSourceType.PLATFORM)

            # Sync trust record before writing the manifest so a trust failure
            # cannot leave an orphaned manifest pointing at a wheel we remove
            # during cleanup.
            self._sync_trust_record(install_dir_name, download_info.sha256, sig_info)
            self._write_manifest(
                plugin_dir=plugin_dir,
                plugin_name=install_dir_name,
                version=download_info.version,
                wheel_filename=download_info.filename,
                sha256=download_info.sha256,
                source=source,
                signature_info=sig_info,
            )

            # Sweep older wheels left behind by previous installs of
            # the same plugin under a different version-stamped name.
            self._remove_stale_wheels(plugin_dir, keep_filename=download_info.filename)

            # Migrate a legacy install that lived under the catalog
            # reference instead of the wheel distribution name (older
            # ggshield versions named the dir after ``plugin_name``).
            # If a directory at ``plugins_dir/<plugin_name>`` exists,
            # is distinct from the new install dir, and looks like a
            # plugin (manifest present), remove it. Otherwise
            # ``_resolve_plugin_dir(plugin_name)`` would keep returning
            # the stale directory and ``status``/``update`` would read
            # the pre-upgrade version.
            self._cleanup_legacy_install_dir(
                catalog_reference=plugin_name,
                current_dir=plugin_dir,
            )

            logger.info("Installed %s v%s", install_dir_name, download_info.version)
            return wheel_path

        finally:
            # No except: pre-swap errors leave the existing install
            # intact and only need temp cleanup (below); post-swap
            # errors leave a verified wheel at ``wheel_path`` that we
            # must not delete, or the user is left with neither the
            # old nor the new wheel. A retry rewrites manifest/trust.
            if temp_path.exists():
                temp_path.unlink()
            if temp_bundle_path is not None and temp_bundle_path.exists():
                temp_bundle_path.unlink()

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
        try:
            metadata = extract_wheel_metadata(wheel_path)
        except WheelError as e:
            raise DownloadError(f"Invalid wheel file: {e}") from e

        # Canonicalise via the wheel filename so the install dir matches
        # what ``download_and_install`` writes for the same package
        # (PEP 503: lower + ``_ -> -``). Without this, a wheel whose
        # METADATA Name is ``Foo_Bar`` lands under ``plugins_dir/Foo_Bar/``
        # while the platform install of the same package lands under
        # ``plugins_dir/foo-bar/``, breaking convergence.
        plugin_name = _wheel_distribution_name(wheel_path.name)
        version = metadata.version
        self._validate_plugin_name(plugin_name)

        # Verify on the caller-provided wheel path — the bundle (if any)
        # lives alongside the source wheel. Copying first would leave a
        # rejected wheel under plugins/<name>/ on STRICT failure.
        sig_info = verify_wheel_signature(wheel_path, signature_mode)

        sha256 = compute_file_sha256(wheel_path)

        plugin_dir = self.plugins_dir / plugin_name
        plugin_dir.mkdir(parents=True, exist_ok=True)

        dest_wheel_path = plugin_dir / wheel_path.name
        self._remove_bundle_files(dest_wheel_path)
        shutil.copy2(wheel_path, dest_wheel_path)

        from ggshield.core.plugin.signature import get_bundle_path

        bundle_path = get_bundle_path(wheel_path)
        if bundle_path is not None:
            shutil.copy2(bundle_path, plugin_dir / bundle_path.name)

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
        self._remove_stale_wheels(plugin_dir, keep_filename=wheel_path.name)

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

        with tempfile.TemporaryDirectory() as temp_dir:
            raw_filename = url.split("/")[-1].split("?")[0]
            try:
                filename = sanitize_wheel_filename(raw_filename)
            except InvalidWheelError:
                # Fallback for URLs whose tail isn't a recognisable wheel
                # filename. The actual wheel name is irrelevant on disk —
                # only the bytes matter for verification.
                filename = "plugin.whl"

            temp_wheel_path = Path(temp_dir) / filename

            try:
                logger.info("Downloading from %s...", url)
                response = requests.get(url, stream=True, timeout=HTTP_TIMEOUT_SECONDS)
                assert_all_https(response, exc_factory=InsecureSourceError)
                response.raise_for_status()

                computed_hash = _stream_to_file(
                    response, temp_wheel_path, MAX_WHEEL_SIZE_BYTES, hash_bytes=True
                )
                assert computed_hash is not None

                if sha256 and computed_hash.lower() != sha256.lower():
                    raise ChecksumMismatchError(sha256, computed_hash)

            except requests.RequestException as e:
                raise DownloadError(f"Failed to download from URL: {e}") from e

            try:
                metadata = extract_wheel_metadata(temp_wheel_path)
            except WheelError as e:
                raise DownloadError(f"Downloaded file is not a valid wheel: {e}") from e

            plugin_name = metadata.name
            version = metadata.version
            self._validate_plugin_name(plugin_name)

            # Fetch sigstore bundle alongside the wheel in the temp dir so
            # verification runs before we touch the final plugin directory.
            self._download_url_bundle(url, temp_wheel_path)

            # Verify before we place anything in the final destination so a
            # STRICT-mode signature failure can't leave a rejected wheel on
            # disk under plugins/<name>/.
            sig_info = verify_wheel_signature(temp_wheel_path, signature_mode)

            plugin_dir = self.plugins_dir / plugin_name
            plugin_dir.mkdir(parents=True, exist_ok=True)

            dest_wheel_path = plugin_dir / temp_wheel_path.name
            self._remove_bundle_files(dest_wheel_path)
            shutil.copy2(temp_wheel_path, dest_wheel_path)

            # Copy the bundle too if one was fetched.
            for ext in (".sigstore", ".sigstore.json"):
                bundle_src = temp_wheel_path.parent / (temp_wheel_path.name + ext)
                if bundle_src.exists():
                    shutil.copy2(bundle_src, plugin_dir / bundle_src.name)
                    break

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
        self._remove_stale_wheels(plugin_dir, keep_filename=dest_wheel_path.name)

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
        github_repo = self._extract_github_repo(url)

        plugin_name, version, wheel_path = self.download_from_url(
            url, sha256, signature_mode=signature_mode
        )

        # Upgrade the provenance record from "url" to "github_release". Use
        # the same tmp+replace path as _write_manifest so a crash mid-write
        # can't corrupt the manifest.
        manifest_path = self.plugins_dir / plugin_name / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["source"] = PluginSource(
            type=PluginSourceType.GITHUB_RELEASE,
            url=url,
            github_repo=github_repo,
            sha256=manifest.get("sha256"),
        ).to_dict()

        tmp_path = manifest_path.with_suffix(".json.tmp")
        try:
            tmp_path.write_text(json.dumps(manifest, indent=2))
            tmp_path.replace(manifest_path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

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
                    timeout=HTTP_TIMEOUT_SECONDS,
                )
                assert_all_https(response, exc_factory=InsecureSourceError)
                response.raise_for_status()

                _stream_to_file(response, artifact_zip_path, MAX_WHEEL_SIZE_BYTES)

            except requests.RequestException as e:
                raise GitHubArtifactError(f"Failed to download artifact: {e}") from e

            # Extract ZIP and find wheel
            extract_dir = temp_dir_path / "extracted"

            try:
                from ggshield.utils.archive import safe_unpack

                safe_unpack(artifact_zip_path, extract_dir)
            except Exception as e:
                raise GitHubArtifactError(f"Failed to extract artifact: {e}") from e

            # Sort so multi-wheel artifacts pick deterministically. Without
            # this, selection depends on filesystem traversal order, which
            # would let a tampered wheel slipped into a multi-wheel artifact
            # win against the legitimate one on some hosts but not others.
            # We can't fully defend against an attacker who has supplanted
            # the upstream artifact, but adding ordering non-determinism
            # on top of it would be strictly worse.
            wheel_files = sorted(extract_dir.glob("**/*.whl"))
            if not wheel_files:
                raise GitHubArtifactError("No wheel file found in artifact")

            if len(wheel_files) > 1:
                logger.warning(
                    "Multiple wheel files found in artifact, using first "
                    "(alphabetical): %s",
                    wheel_files[0].name,
                )

            temp_wheel_path = wheel_files[0]

            try:
                metadata = extract_wheel_metadata(temp_wheel_path)
            except WheelError as e:
                raise DownloadError(f"Invalid wheel in artifact: {e}") from e

            plugin_name = metadata.name
            version = metadata.version
            self._validate_plugin_name(plugin_name)

            # Verify on the temp path before we touch plugin_dir — a STRICT
            # signature failure must not leave a rejected wheel on disk.
            sig_info = verify_wheel_signature(temp_wheel_path, signature_mode)

            sha256 = compute_file_sha256(temp_wheel_path)

            plugin_dir = self.plugins_dir / plugin_name
            plugin_dir.mkdir(parents=True, exist_ok=True)

            dest_wheel_path = plugin_dir / temp_wheel_path.name
            self._remove_bundle_files(dest_wheel_path)
            shutil.copy2(temp_wheel_path, dest_wheel_path)

            for ext in (".sigstore", ".sigstore.json"):
                bundle_src = temp_wheel_path.parent / (temp_wheel_path.name + ext)
                if bundle_src.exists():
                    shutil.copy2(bundle_src, plugin_dir / bundle_src.name)
                    break

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
        self._remove_stale_wheels(plugin_dir, keep_filename=dest_wheel_path.name)

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
        self._remove_extract_cache(plugin_dir.name)

        logger.info("Uninstalled plugin: %s", plugin_name)
        return True

    def _remove_extract_cache(self, plugin_dir_name: str) -> None:
        """Best-effort removal of extracted wheel cache for an uninstalled plugin."""
        cache_dir = get_cache_dir() / "plugins" / plugin_dir_name
        try:
            shutil.rmtree(cache_dir)
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.debug(
                "Failed to remove plugin extraction cache %s: %s", cache_dir, exc
            )

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
        """Resolve a plugin directory from a package or entry point name.

        Prefer the direct path only when it actually looks like a plugin
        install (``manifest.json`` present). A bare ``plugins_dir/<name>/``
        without a manifest is treated as residue — typically a stale dir
        left behind by an aborted install or hand-created by the user —
        and falls through to the entry-point scan so the real install
        (which may live under the wheel's distribution-name directory)
        still resolves.
        """
        plugin_dir = self.plugins_dir / plugin_name
        if plugin_dir.is_dir() and (plugin_dir / "manifest.json").exists():
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
        plugin_dir = self._resolve_plugin_dir(plugin_name)
        # Hash the on-disk wheel, not manifest["sha256"]: feeding the
        # manifest value back into is_trusted is a tautology (trust
        # record + manifest were written from the same digest), so a
        # post-install wheel tamper would still render as "trusted".
        if wheel_path is not None and plugin_dir is not None:
            try:
                disk_sha256 = compute_file_sha256(wheel_path)
            except OSError:
                disk_sha256 = None
            if disk_sha256 is not None:
                trusted_unsigned = self.trust_store.is_trusted(
                    plugin_dir.name, disk_sha256
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
            return PluginSource(type=PluginSourceType.PLATFORM)

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
        tmp_path = manifest_path.with_suffix(".json.tmp")
        try:
            tmp_path.write_text(json.dumps(manifest, indent=2))
            tmp_path.replace(manifest_path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

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
                response = requests.get(
                    bundle_url, stream=True, timeout=HTTP_TIMEOUT_SECONDS
                )
                assert_all_https(response, exc_factory=InsecureSourceError)
                response.raise_for_status()

                _stream_to_file(response, bundle_path, MAX_BUNDLE_SIZE_BYTES)

                logger.info("Downloaded signature bundle from %s", bundle_url)
                return bundle_path
            except (requests.RequestException, InsecureSourceError, DownloadError):
                continue

        logger.debug("No signature bundle found at URL conventions for %s", wheel_url)
        return None

    def _remove_bundle_files(self, wheel_path: Path) -> None:
        """Remove any bundle sidecars associated with a wheel path."""
        for ext in (".sigstore", ".sigstore.json"):
            bundle = wheel_path.parent / (wheel_path.name + ext)
            if bundle.exists():
                bundle.unlink()

    def _remove_stale_wheels(self, plugin_dir: Path, keep_filename: str) -> None:
        """Remove old wheels left over from a previous install.

        Upgrades from ``foo-1.0-py3-none-any.whl`` to
        ``foo-2.0-py3-none-any.whl`` write the new wheel under a new
        name and update the manifest to point at it — but they don't
        remove the old wheel file. Without this sweep, the plugin
        directory accumulates one stale wheel + sidecar per upgrade.
        The manifest still routes loading to the right wheel, but the
        stale files inflate disk usage and complicate any future
        audit ("which of these three wheels is the one ggshield is
        actually running?").

        Only ``*.whl`` files whose name differs from ``keep_filename``
        are touched, along with their ``.sigstore`` / ``.sigstore.json``
        sidecars. Anything else in ``plugin_dir`` (manifest.json,
        user-dropped fixtures, the kept wheel + its sidecars) is left
        in place.
        """
        if not plugin_dir.is_dir():
            return
        for entry in plugin_dir.iterdir():
            if not entry.is_file():
                continue
            if entry.suffix != ".whl" or entry.name == keep_filename:
                continue
            try:
                entry.unlink()
            except OSError as exc:
                logger.warning("Failed to remove stale wheel %s: %s", entry, exc)
                continue
            self._remove_bundle_files(entry)

    def _cleanup_failed_install(self, wheel_path: Path) -> None:
        """Remove wheel and bundle files after a failed install."""
        if wheel_path.exists():
            wheel_path.unlink()

        self._remove_bundle_files(wheel_path)

    # Manifest ``source.type`` values that signal "this directory was
    # written by a previous platform install of the same plugin and is
    # safe to migrate away from in place". Anything else — ``local_file``,
    # ``url``, ``github_release``, ``github_artifact``, or a manifest we
    # can't parse — is a legitimate user-managed install that must not
    # be deleted just because its directory name happens to collide with
    # the current catalog reference.
    _LEGACY_PLATFORM_SOURCE_TYPES = frozenset(
        {
            PluginSourceType.PLATFORM.value,
            # Manifests written by ggshield < 1.50 used the old enum value.
            "gitguardian_api",
        }
    )

    def _cleanup_legacy_install_dir(
        self, catalog_reference: str, current_dir: Path
    ) -> None:
        """Remove a stale install dir named after the catalog reference.

        Older ggshield builds named the on-disk plugin directory after
        the catalog reference (``plugin_name``) regardless of the
        wheel's distribution name. The current install dir comes from
        the wheel distribution name, so a user upgrading from one of
        those builds can end up with two directories: a stale legacy
        one keyed on ``catalog_reference`` and the current one keyed
        on the wheel name. Without cleanup the entry-point fallback in
        :meth:`_resolve_plugin_dir` would still find the new install,
        but ``status`` / ``update`` queries that hit the catalog
        reference first would keep reading the pre-upgrade manifest.

        We only remove the legacy dir when ALL of the following hold:
        - it's distinct from ``current_dir`` (the new install we just
          finished writing),
        - it has a ``manifest.json`` we can parse, and
        - that manifest's ``source.type`` says the directory was
          previously written by a platform install (``platform`` or
          the legacy ``gitguardian_api`` value).

        The last condition is the safety net: if the catalog reference
        collides with the directory name of a real ``local_file`` /
        ``url`` / ``github_release`` install (e.g. the user grabbed a
        wheel called ``tokenscanner`` from disk and the new catalog
        reference is also ``tokenscanner`` while the platform wheel's
        distribution is ``ggshield-tokenscanner``), we leave the
        user-managed install untouched.
        """
        if not self._is_valid_plugin_name(catalog_reference):
            return
        legacy_dir = self.plugins_dir / catalog_reference
        if not legacy_dir.exists() or legacy_dir.resolve() == current_dir.resolve():
            return
        manifest_path = legacy_dir / "manifest.json"
        if not manifest_path.exists():
            return
        try:
            manifest = json.loads(manifest_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            # Unreadable / malformed manifest is ambiguous evidence —
            # could be a half-written platform install but could also
            # be a user-owned directory. Leave it alone and let the
            # entry-point fallback in ``_resolve_plugin_dir`` route
            # callers to the new install instead.
            logger.warning(
                "Refusing to remove %s: cannot parse manifest (%s)", legacy_dir, exc
            )
            return
        legacy_source = (manifest.get("source") or {}).get("type")
        if legacy_source not in self._LEGACY_PLATFORM_SOURCE_TYPES:
            logger.info(
                "Leaving %s in place: manifest source.type=%r is user-managed",
                legacy_dir,
                legacy_source,
            )
            return
        try:
            shutil.rmtree(legacy_dir)
        except OSError as exc:
            logger.warning("Failed to remove stale plugin dir %s: %s", legacy_dir, exc)
            return
        # Drop the trust record for the legacy entry so a future install
        # under the catalog reference doesn't inherit a stale SHA from
        # the now-removed wheel.
        try:
            self.trust_store.revoke_plugin(catalog_reference)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "Failed to revoke trust record for %s: %s", catalog_reference, exc
            )
        logger.info("Removed legacy plugin dir %s", legacy_dir)

    def _extract_github_repo(self, url: str) -> Optional[str]:
        """Extract owner/repo from a GitHub URL."""
        match = re.match(r"https://github\.com/([^/]+)/([^/]+)", url)
        if not match:
            return None
        owner, repo = match.group(1), match.group(2)
        if repo.endswith(".git"):
            repo = repo[: -len(".git")]
        # Reject path-traversal-like segments; the repo value is later
        # interpolated into api.github.com URLs and stored in manifests.
        if owner in {"", ".", ".."} or repo in {"", ".", ".."}:
            return None
        if "/" in owner or "/" in repo or "\\" in owner or "\\" in repo:
            return None
        return f"{owner}/{repo}"

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
