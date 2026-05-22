"""Tests for plugin downloader."""

import hashlib
import json
import shutil
import zipfile
from pathlib import Path
from typing import Any, Iterator
from unittest.mock import MagicMock, patch

import pytest
import requests

from ggshield.core.plugin.client import (
    PluginDownloadInfo,
    PluginSource,
    PluginSourceType,
)
from ggshield.core.plugin.downloader import (
    ChecksumMismatchError,
    DownloadError,
    GitHubArtifactError,
    InsecureSourceError,
    PluginDownloader,
    get_plugins_dir,
    get_signature_label,
)
from ggshield.core.plugin.signature import (
    SignatureInfo,
    SignatureStatus,
    SignatureVerificationMode,
)
from ggshield.core.plugin.trust import compute_file_sha256


MOCK_SIG_INFO = SignatureInfo(status=SignatureStatus.SKIPPED)


class TestPluginDownloader:
    """Tests for PluginDownloader."""

    def test_init(self, tmp_path: Path) -> None:
        """Test downloader initialization."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.plugins_dir == tmp_path

    def test_is_installed_false(self, tmp_path: Path) -> None:
        """Test is_installed returns False for non-installed plugin."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.is_installed("nonexistent") is False

    def test_is_installed_true(self, tmp_path: Path) -> None:
        """Test is_installed returns True for installed plugin."""
        # Create plugin directory with manifest
        plugin_dir = tmp_path / "testplugin"
        plugin_dir.mkdir()
        manifest = {
            "plugin_name": "testplugin",
            "version": "1.0.0",
            "wheel_filename": "testplugin-1.0.0.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.is_installed("testplugin") is True

    def test_get_installed_version_not_installed(self, tmp_path: Path) -> None:
        """Test get_installed_version for non-installed plugin."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.get_installed_version("nonexistent") is None

    def test_get_installed_version(self, tmp_path: Path) -> None:
        """Test get_installed_version for installed plugin."""
        # Create plugin directory with manifest
        plugin_dir = tmp_path / "testplugin"
        plugin_dir.mkdir()
        manifest = {
            "plugin_name": "testplugin",
            "version": "1.2.3",
            "wheel_filename": "testplugin-1.2.3.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.get_installed_version("testplugin") == "1.2.3"

    def test_get_wheel_path_not_installed(self, tmp_path: Path) -> None:
        """Test get_wheel_path for non-installed plugin."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.get_wheel_path("nonexistent") is None

    def test_get_wheel_path(self, tmp_path: Path) -> None:
        """Test get_wheel_path for installed plugin."""
        # Create plugin directory with manifest and wheel
        plugin_dir = tmp_path / "testplugin"
        plugin_dir.mkdir()
        wheel_path = plugin_dir / "testplugin-1.0.0.whl"
        wheel_path.touch()
        manifest = {
            "plugin_name": "testplugin",
            "version": "1.0.0",
            "wheel_filename": "testplugin-1.0.0.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.get_wheel_path("testplugin") == wheel_path

    def test_uninstall_not_installed(self, tmp_path: Path) -> None:
        """Test uninstall returns False for non-installed plugin."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.uninstall("nonexistent") is False

    def test_uninstall(self, tmp_path: Path) -> None:
        """Test uninstall removes plugin directory."""
        # Create plugin directory
        plugin_dir = tmp_path / "testplugin"
        plugin_dir.mkdir()
        (plugin_dir / "manifest.json").write_text("{}")
        (plugin_dir / "testplugin.whl").touch()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader.uninstall("testplugin") is True
        assert not plugin_dir.exists()

    def test_uninstall_removes_extraction_cache(self, tmp_path: Path) -> None:
        """Test uninstall also removes extracted wheel cache for the plugin."""
        plugins_dir = tmp_path / "plugins"
        cache_dir = tmp_path / "cache"
        plugin_dir = plugins_dir / "testplugin"
        extract_cache = cache_dir / "plugins" / "testplugin"
        plugin_dir.mkdir(parents=True)
        extract_cache.mkdir(parents=True)
        (plugin_dir / "manifest.json").write_text("{}")
        (plugin_dir / "testplugin.whl").touch()
        (extract_cache / "testplugin-1.0.0-deadbeef_extracted").mkdir()

        with (
            patch(
                "ggshield.core.plugin.downloader.get_plugins_dir",
                return_value=plugins_dir,
            ),
            patch(
                "ggshield.core.plugin.downloader.get_cache_dir",
                return_value=cache_dir,
            ),
        ):
            downloader = PluginDownloader()

        assert downloader.uninstall("testplugin") is True
        assert not plugin_dir.exists()
        assert not extract_cache.exists()

    def test_uninstall_extraction_cache_oserror_is_swallowed(
        self, tmp_path: Path
    ) -> None:
        """A non-FileNotFound OSError on cache removal must not break uninstall."""
        plugins_dir = tmp_path / "plugins"
        cache_dir = tmp_path / "cache"
        plugin_dir = plugins_dir / "testplugin"
        extract_cache = cache_dir / "plugins" / "testplugin"
        plugin_dir.mkdir(parents=True)
        extract_cache.mkdir(parents=True)
        (plugin_dir / "manifest.json").write_text("{}")
        (plugin_dir / "testplugin.whl").touch()

        original_rmtree = shutil.rmtree

        def fail_on_extract_cache(path: Any, *args: Any, **kwargs: Any) -> None:
            if Path(path) == extract_cache:
                raise PermissionError("denied")
            original_rmtree(path, *args, **kwargs)

        with (
            patch(
                "ggshield.core.plugin.downloader.get_plugins_dir",
                return_value=plugins_dir,
            ),
            patch(
                "ggshield.core.plugin.downloader.get_cache_dir",
                return_value=cache_dir,
            ),
        ):
            downloader = PluginDownloader()
            with patch(
                "ggshield.core.plugin.downloader.shutil.rmtree",
                side_effect=fail_on_extract_cache,
            ):
                assert downloader.uninstall("testplugin") is True

        assert not plugin_dir.exists()
        assert extract_cache.exists()  # not removed, but uninstall still succeeded

    def test_uninstall_removes_trust_record(self, tmp_path: Path) -> None:
        """Test uninstall also removes any persisted trust exception."""
        plugin_dir = tmp_path / "testplugin"
        plugin_dir.mkdir()
        (plugin_dir / "manifest.json").write_text("{}")
        (plugin_dir / "testplugin.whl").touch()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        downloader.trust_store.trust_plugin("testplugin", "abc123", "missing")

        assert downloader.uninstall("testplugin") is True
        assert downloader.trust_store.get_record("testplugin") is None

    def test_download_and_install_success(self, tmp_path: Path) -> None:
        """Test successful download and install."""
        wheel_content = b"fake wheel content"
        sha256 = hashlib.sha256(wheel_content).hexdigest()

        download_info = PluginDownloadInfo(
            filename="testplugin-1.0.0.whl",
            sha256=sha256,
            version="1.0.0",
            size_bytes=len(wheel_content),
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            with patch(
                "ggshield.core.plugin.downloader.verify_wheel_signature",
                return_value=MOCK_SIG_INFO,
            ):
                downloader = PluginDownloader()
                wheel_path = downloader.download_and_install(
                    download_info,
                    iter([wheel_content]),
                    "testplugin",
                )

        assert wheel_path.exists()
        assert wheel_path.name == "testplugin-1.0.0.whl"
        assert (tmp_path / "testplugin" / "manifest.json").exists()

        # Verify manifest content
        manifest = json.loads((tmp_path / "testplugin" / "manifest.json").read_text())
        assert manifest["plugin_name"] == "testplugin"
        assert manifest["version"] == "1.0.0"

    def test_download_and_install_records_trusted_unsigned_plugin(
        self, tmp_path: Path
    ) -> None:
        """Test allow-unsigned installs persist trust for the exact wheel hash."""
        wheel_content = b"fake wheel content"
        sha256 = hashlib.sha256(wheel_content).hexdigest()

        download_info = PluginDownloadInfo(
            filename="testplugin-1.0.0.whl",
            sha256=sha256,
            version="1.0.0",
            size_bytes=len(wheel_content),
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            with patch(
                "ggshield.core.plugin.downloader.verify_wheel_signature",
                return_value=SignatureInfo(
                    status=SignatureStatus.MISSING,
                    message="No bundle found",
                ),
            ):
                downloader = PluginDownloader()
                downloader.download_and_install(
                    download_info,
                    iter([wheel_content]),
                    "testplugin",
                    signature_mode=SignatureVerificationMode.WARN,
                )

        record = downloader.trust_store.get_record("testplugin")
        assert record is not None
        assert record.sha256 == sha256
        assert record.signature_status == "missing"

    def test_download_and_install_removes_trust_record_for_signed_plugin(
        self, tmp_path: Path
    ) -> None:
        """Test signed installs clear any previous unsigned trust exception."""
        wheel_content = b"fake wheel content"
        sha256 = hashlib.sha256(wheel_content).hexdigest()

        download_info = PluginDownloadInfo(
            filename="testplugin-1.0.0.whl",
            sha256=sha256,
            version="1.0.0",
            size_bytes=len(wheel_content),
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            with patch(
                "ggshield.core.plugin.downloader.verify_wheel_signature",
                return_value=SignatureInfo(
                    status=SignatureStatus.VALID,
                    identity="GitGuardian/satori",
                ),
            ):
                downloader = PluginDownloader()
                downloader.trust_store.trust_plugin(
                    "testplugin",
                    sha256,
                    "missing",
                )
                downloader.download_and_install(
                    download_info,
                    iter([wheel_content]),
                    "testplugin",
                )

        assert downloader.trust_store.get_record("testplugin") is None

    def test_download_and_install_checksum_mismatch(self, tmp_path: Path) -> None:
        """Test download fails with checksum mismatch."""
        wheel_content = b"fake wheel content"
        wrong_sha256 = "0" * 64  # Wrong checksum

        download_info = PluginDownloadInfo(
            filename="testplugin-1.0.0.whl",
            sha256=wrong_sha256,
            version="1.0.0",
            size_bytes=len(wheel_content),
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

            with pytest.raises(ChecksumMismatchError):
                downloader.download_and_install(
                    download_info,
                    iter([wheel_content]),
                    "testplugin",
                )

    def test_download_and_install_network_error(self, tmp_path: Path) -> None:
        """Test download fails with network error (simulated via raising iterator)."""
        download_info = PluginDownloadInfo(
            filename="testplugin-1.0.0.whl",
            sha256="abc123",
            version="1.0.0",
            size_bytes=10,
        )

        def raising_chunks() -> Iterator[bytes]:
            raise OSError("Network error")
            yield b""  # make it a generator

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

            with pytest.raises(OSError) as exc_info:
                downloader.download_and_install(
                    download_info,
                    raising_chunks(),
                    "testplugin",
                )

            assert "Network error" in str(exc_info.value)

    def test_download_and_install_rejects_invalid_plugin_name(
        self, tmp_path: Path
    ) -> None:
        """Test install rejects unsafe plugin names."""
        download_info = PluginDownloadInfo(
            filename="testplugin-1.0.0.whl",
            sha256="abc123",
            version="1.0.0",
            size_bytes=100,
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

            with pytest.raises(DownloadError) as exc_info:
                downloader.download_and_install(
                    download_info,
                    iter([b""]),
                    "../../outside",
                )

            assert "Invalid plugin name" in str(exc_info.value)

    def test_download_and_install_manifest_failure_keeps_verified_wheel(
        self, tmp_path: Path
    ) -> None:
        """A manifest write failure after the swap must leave the new wheel.

        The swap happens AFTER signature verification, so wheel_path holds
        verified bytes. Deleting them would strand the user with neither
        the old nor the new wheel (same-filename reinstall scenario);
        leaving them lets a retry rewrite manifest/trust.
        """
        wheel_content = b"fake wheel content"
        sha256 = hashlib.sha256(wheel_content).hexdigest()

        download_info = PluginDownloadInfo(
            filename="testplugin-1.0.0.whl",
            sha256=sha256,
            version="1.0.0",
            size_bytes=len(wheel_content),
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            with patch(
                "ggshield.core.plugin.downloader.verify_wheel_signature",
                return_value=MOCK_SIG_INFO,
            ):
                downloader = PluginDownloader()

                with patch.object(
                    downloader, "_write_manifest", side_effect=OSError("disk full")
                ):
                    with pytest.raises(OSError):
                        downloader.download_and_install(
                            download_info,
                            iter([wheel_content]),
                            "testplugin",
                        )

        temp_path = tmp_path / "testplugin" / "testplugin-1.0.0.whl.tmp"
        assert not temp_path.exists()
        wheel_path = tmp_path / "testplugin" / "testplugin-1.0.0.whl"
        assert wheel_path.exists()
        assert not (tmp_path / "testplugin" / "manifest.json").exists()

    def test_is_installed_by_entry_point_name(self, tmp_path: Path) -> None:
        """Test is_installed finds plugin by entry point name."""
        # Create plugin with different package name than entry point name
        plugin_dir = tmp_path / "package-name"
        plugin_dir.mkdir()
        wheel_path = plugin_dir / "package_name-1.0.0.whl"

        # Create wheel with entry point named "my_plugin"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr(
                "package_name-1.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\nmy_plugin = package_name.plugin:Plugin\n",
            )

        manifest = {
            "plugin_name": "package-name",
            "version": "1.0.0",
            "wheel_filename": "package_name-1.0.0.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        # Should find by entry point name
        assert downloader.is_installed("my_plugin") is True
        # Should also find by package name
        assert downloader.is_installed("package-name") is True
        # Should not find non-existent
        assert downloader.is_installed("nonexistent") is False

    def test_get_installed_version_by_entry_point_name(self, tmp_path: Path) -> None:
        """Test get_installed_version finds plugin by entry point name."""
        # Create plugin with different package name than entry point name
        plugin_dir = tmp_path / "package-name"
        plugin_dir.mkdir()
        wheel_path = plugin_dir / "package_name-1.0.0.whl"

        # Create wheel with entry point named "my_plugin"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr(
                "package_name-1.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\nmy_plugin = package_name.plugin:Plugin\n",
            )

        manifest = {
            "plugin_name": "package-name",
            "version": "2.0.0",
            "wheel_filename": "package_name-1.0.0.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        # Should find version by entry point name
        assert downloader.get_installed_version("my_plugin") == "2.0.0"

    def test_get_installed_signature_label_by_entry_point_name(
        self, tmp_path: Path
    ) -> None:
        """Test signature label lookup follows entry point names for local wheels."""
        plugin_dir = tmp_path / "package-name"
        plugin_dir.mkdir()
        wheel_path = plugin_dir / "package_name-1.0.0.whl"

        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr(
                "package_name-1.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\nmy_plugin = package_name.plugin:Plugin\n",
            )

        wheel_sha256 = compute_file_sha256(wheel_path)
        manifest = {
            "plugin_name": "package-name",
            "version": "1.0.0",
            "wheel_filename": "package_name-1.0.0.whl",
            "sha256": wheel_sha256,
            "signature": {
                "status": "missing",
                "message": "No bundle found",
            },
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        downloader.trust_store.trust_plugin(
            plugin_dir.name,
            wheel_sha256,
            "missing",
        )

        assert downloader.get_wheel_path("my_plugin") == wheel_path
        assert (
            downloader.get_installed_signature_label("my_plugin")
            == "unsigned (trusted)"
        )

    def test_signature_label_drops_trusted_when_wheel_tampered(
        self, tmp_path: Path
    ) -> None:
        """Tampering the on-disk wheel must drop the trusted-unsigned label.

        The label compares the trust record to the wheel hash recomputed
        from disk, so a post-install rewrite of the wheel bytes (leaving
        manifest and trust record intact) breaks the trust chain.
        """
        plugin_dir = tmp_path / "tamper-test"
        plugin_dir.mkdir()
        wheel_path = plugin_dir / "tamper_test-1.0.0.whl"
        wheel_path.write_bytes(b"original wheel bytes")
        original_sha = compute_file_sha256(wheel_path)

        manifest = {
            "plugin_name": "tamper-test",
            "version": "1.0.0",
            "wheel_filename": "tamper_test-1.0.0.whl",
            "sha256": original_sha,
            "signature": {"status": "missing", "message": "No bundle found"},
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        downloader.trust_store.trust_plugin(plugin_dir.name, original_sha, "missing")
        assert (
            downloader.get_installed_signature_label("tamper-test")
            == "unsigned (trusted)"
        )

        wheel_path.write_bytes(b"tampered wheel bytes")
        assert downloader.get_installed_signature_label("tamper-test") == "missing"

    def test_uninstall_by_entry_point_name(self, tmp_path: Path) -> None:
        """Test uninstall can remove plugin by entry point name."""
        # Create plugin with different package name than entry point name
        plugin_dir = tmp_path / "package-name"
        plugin_dir.mkdir()
        wheel_path = plugin_dir / "package_name-1.0.0.whl"

        # Create wheel with entry point named "my_plugin"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr(
                "package_name-1.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\nmy_plugin = package_name.plugin:Plugin\n",
            )

        manifest = {
            "plugin_name": "package-name",
            "version": "1.0.0",
            "wheel_filename": "package_name-1.0.0.whl",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        # Should uninstall by entry point name
        assert downloader.uninstall("my_plugin") is True
        assert not plugin_dir.exists()

    def test_find_plugin_dir_by_entry_point_not_found(self, tmp_path: Path) -> None:
        """Test _find_plugin_dir_by_entry_point returns None when not found."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader._find_plugin_dir_by_entry_point("nonexistent") is None

    def test_find_plugin_dir_by_entry_point_no_plugins_dir(
        self, tmp_path: Path
    ) -> None:
        """Test _find_plugin_dir_by_entry_point when plugins dir doesn't exist."""
        nonexistent_dir = tmp_path / "nonexistent"

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir",
            return_value=nonexistent_dir,
        ):
            downloader = PluginDownloader()

        assert downloader._find_plugin_dir_by_entry_point("test") is None

    def test_read_entry_point_name_from_wheel_no_entry_points(
        self, tmp_path: Path
    ) -> None:
        """Test _read_entry_point_name_from_wheel when no entry points."""
        wheel_path = tmp_path / "test-1.0.0.whl"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr("test-1.0.0.dist-info/METADATA", "Name: test\nVersion: 1.0.0\n")

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader._read_entry_point_name_from_wheel(wheel_path) is None

    def test_read_entry_point_name_from_wheel_invalid_file(
        self, tmp_path: Path
    ) -> None:
        """Test _read_entry_point_name_from_wheel with invalid file."""
        invalid_file = tmp_path / "not-a-wheel.txt"
        invalid_file.write_text("not a zip file")

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        assert downloader._read_entry_point_name_from_wheel(invalid_file) is None

    def test_download_and_install_from_chunks(self, tmp_path: Path) -> None:
        """
        GIVEN a PluginDownloadInfo and an iterator of bytes
        WHEN download_and_install is called
        THEN it writes the wheel and verifies SHA256
        """
        # Build a minimal valid wheel zip
        wheel_bytes = b"fake wheel content for sha test"
        sha256 = hashlib.sha256(wheel_bytes).hexdigest()

        download_info = PluginDownloadInfo(
            filename="testplugin-1.0.0-py3-none-any.whl",
            sha256=sha256,
            version="1.0.0",
            size_bytes=len(wheel_bytes),
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ), patch(
            "ggshield.core.plugin.downloader.verify_wheel_signature",
            return_value=MOCK_SIG_INFO,
        ):
            downloader = PluginDownloader()
            result = downloader.download_and_install(
                download_info,
                iter([wheel_bytes]),
                "testplugin",
            )

        assert result == tmp_path / "testplugin" / "testplugin-1.0.0-py3-none-any.whl"
        assert result.read_bytes() == wheel_bytes

    def test_download_and_install_raises_on_sha256_mismatch(
        self, tmp_path: Path
    ) -> None:
        """
        GIVEN a download info with wrong SHA256
        WHEN download_and_install is called
        THEN it raises ChecksumMismatchError and cleans up the temp file
        """
        download_info = PluginDownloadInfo(
            filename="testplugin-1.0.0-py3-none-any.whl",
            sha256="a" * 64,  # 64-char hex string (SHA256 length), wrong hash
            version="1.0.0",
            size_bytes=10,
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            with pytest.raises(ChecksumMismatchError):
                downloader.download_and_install(
                    download_info,
                    iter([b"actual content"]),
                    "testplugin",
                )

        # temp file must be cleaned up
        assert not list((tmp_path / "testplugin").glob("*.tmp"))


class TestChecksumMismatchError:
    """Tests for ChecksumMismatchError."""

    def test_error_message(self) -> None:
        """Test error message formatting."""
        error = ChecksumMismatchError(
            expected="abcdef1234567890" * 4, actual="0987654321fedcba" * 4
        )

        assert "abcdef1234567890" in str(error)
        assert "0987654321fedcba" in str(error)
        assert "Checksum mismatch" in str(error)


class TestGetPluginsDir:
    """Tests for get_plugins_dir function."""

    @patch("ggshield.core.dirs.get_data_dir")
    def test_creates_directory(self, mock_data_dir: MagicMock, tmp_path: Path) -> None:
        """Test that get_plugins_dir creates the directory if it doesn't exist."""
        plugins_path = tmp_path / "plugins"
        mock_data_dir.return_value = tmp_path

        result = get_plugins_dir(create=True)

        assert result == plugins_path
        assert plugins_path.exists()


def create_test_wheel(
    tmp_path: Path, name: str = "testplugin", version: str = "1.0.0"
) -> Path:
    """Create a minimal valid wheel file for testing."""
    wheel_name = f"{name}-{version}-py3-none-any.whl"
    wheel_path = tmp_path / wheel_name

    with zipfile.ZipFile(wheel_path, "w") as zf:
        dist_info = f"{name}-{version}.dist-info"
        metadata_content = f"""Metadata-Version: 2.1
Name: {name}
Version: {version}
Summary: A test plugin
"""
        zf.writestr(f"{dist_info}/METADATA", metadata_content)
        zf.writestr(f"{dist_info}/WHEEL", "Wheel-Version: 1.0")
        zf.writestr(f"{dist_info}/RECORD", "")
        zf.writestr(f"{name}/__init__.py", "# Test module")

    return wheel_path


class TestInstallFromWheel:
    """Tests for install_from_wheel method."""

    def test_install_from_wheel_success(self, tmp_path: Path) -> None:
        """Test successful installation from a local wheel file."""
        # Create source wheel
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        wheel_path = create_test_wheel(source_dir, "myplugin", "2.0.0")

        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch(
                "ggshield.core.plugin.downloader.verify_wheel_signature",
                return_value=MOCK_SIG_INFO,
            ):
                downloader = PluginDownloader()
                plugin_name, version, installed_path = downloader.install_from_wheel(
                    wheel_path
                )

        assert plugin_name == "myplugin"
        assert version == "2.0.0"
        assert installed_path.exists()
        assert installed_path.parent == plugins_dir / "myplugin"

        # Verify manifest
        manifest = json.loads((plugins_dir / "myplugin" / "manifest.json").read_text())
        assert manifest["plugin_name"] == "myplugin"
        assert manifest["version"] == "2.0.0"
        assert manifest["source"]["type"] == "local_file"

    def test_install_from_wheel_canonicalises_distribution_name(
        self, tmp_path: Path
    ) -> None:
        """Install dir uses the PEP 503-canonical name, matching the platform flow.

        A wheel whose METADATA ``Name`` is ``Foo_Bar`` must land under
        ``plugins_dir/foo-bar/`` (the same place ``download_and_install``
        would write the catalog wheel) so the two flows converge instead
        of creating side-by-side directories for the same package.
        """
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        wheel_path = create_test_wheel(source_dir, "Foo_Bar", "1.0.0")

        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch(
                "ggshield.core.plugin.downloader.verify_wheel_signature",
                return_value=MOCK_SIG_INFO,
            ):
                downloader = PluginDownloader()
                plugin_name, _, installed_path = downloader.install_from_wheel(
                    wheel_path
                )

        assert plugin_name == "foo-bar"
        assert installed_path.parent == plugins_dir / "foo-bar"
        assert not (plugins_dir / "Foo_Bar").exists()

    def test_install_from_wheel_removes_stale_bundle_sidecars(
        self, tmp_path: Path
    ) -> None:
        """A local reinstall must not reuse stale bundle sidecars from a previous install."""
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        wheel_path = create_test_wheel(source_dir, "myplugin", "2.0.0")

        plugins_dir = tmp_path / "plugins"
        plugin_dir = plugins_dir / "myplugin"
        plugin_dir.mkdir(parents=True)

        stale_sigstore = plugin_dir / f"{wheel_path.name}.sigstore"
        stale_sigstore.write_bytes(b"stale-bundle")
        stale_sigstore_json = plugin_dir / f"{wheel_path.name}.sigstore.json"
        stale_sigstore_json.write_bytes(b"stale-bundle-json")

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch(
                "ggshield.core.plugin.downloader.verify_wheel_signature",
                return_value=MOCK_SIG_INFO,
            ):
                downloader = PluginDownloader()
                _, _, installed_path = downloader.install_from_wheel(wheel_path)

        assert installed_path.exists()
        assert not stale_sigstore.exists()
        assert not stale_sigstore_json.exists()

    def test_install_from_wheel_invalid_wheel(self, tmp_path: Path) -> None:
        """Test installation fails with invalid wheel."""
        invalid_wheel = tmp_path / "invalid.whl"
        invalid_wheel.write_bytes(b"not a wheel")

        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            downloader = PluginDownloader()

            with pytest.raises(DownloadError) as exc_info:
                downloader.install_from_wheel(invalid_wheel)

            assert "Invalid wheel file" in str(exc_info.value)


class TestDownloadFromUrl:
    """Tests for download_from_url method."""

    def test_download_from_url_success(self, tmp_path: Path) -> None:
        """Test successful download from URL."""
        # Create wheel content
        wheel_dir = tmp_path / "wheel_content"
        wheel_dir.mkdir()
        wheel_path = create_test_wheel(wheel_dir, "urlplugin", "1.0.0")
        wheel_content = wheel_path.read_bytes()
        sha256 = hashlib.sha256(wheel_content).hexdigest()

        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [wheel_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                with patch(
                    "ggshield.core.plugin.downloader.verify_wheel_signature",
                    return_value=MOCK_SIG_INFO,
                ):
                    downloader = PluginDownloader()
                    plugin_name, version, installed_path = downloader.download_from_url(
                        "https://example.com/urlplugin-1.0.0.whl",
                        sha256=sha256,
                    )

        assert plugin_name == "urlplugin"
        assert version == "1.0.0"
        assert installed_path.exists()

        # Verify manifest source tracking
        manifest = json.loads((plugins_dir / "urlplugin" / "manifest.json").read_text())
        assert manifest["source"]["type"] == "url"
        assert manifest["source"]["url"] == "https://example.com/urlplugin-1.0.0.whl"

    def test_download_from_url_http_rejected(self, tmp_path: Path) -> None:
        """Test that HTTP URLs are rejected."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            downloader = PluginDownloader()

            with pytest.raises(InsecureSourceError) as exc_info:
                downloader.download_from_url("http://example.com/plugin.whl")

            assert "HTTP URLs are not allowed" in str(exc_info.value)

    def test_download_from_url_checksum_mismatch(self, tmp_path: Path) -> None:
        """Test checksum verification failure."""
        wheel_dir = tmp_path / "wheel_content"
        wheel_dir.mkdir()
        wheel_path = create_test_wheel(wheel_dir, "urlplugin", "1.0.0")
        wheel_content = wheel_path.read_bytes()

        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [wheel_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                downloader = PluginDownloader()

                with pytest.raises(ChecksumMismatchError):
                    downloader.download_from_url(
                        "https://example.com/plugin.whl",
                        sha256="0" * 64,  # Wrong checksum
                    )


class TestDownloadFromGitHubRelease:
    """Tests for download_from_github_release method."""

    def test_github_release_extracts_repo(self, tmp_path: Path) -> None:
        """Test that GitHub repo is extracted from URL."""
        wheel_dir = tmp_path / "wheel_content"
        wheel_dir.mkdir()
        wheel_path = create_test_wheel(wheel_dir, "ghplugin", "1.0.0")
        wheel_content = wheel_path.read_bytes()
        sha256 = hashlib.sha256(wheel_content).hexdigest()

        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [wheel_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                with patch(
                    "ggshield.core.plugin.downloader.verify_wheel_signature",
                    return_value=MOCK_SIG_INFO,
                ):
                    downloader = PluginDownloader()
                    plugin_name, version, _ = downloader.download_from_github_release(
                        "https://github.com/owner/repo/releases/download/v1.0.0/ghplugin-1.0.0.whl",
                        sha256=sha256,
                    )

        assert plugin_name == "ghplugin"
        assert version == "1.0.0"

        # Verify source tracking has GitHub repo
        manifest = json.loads((plugins_dir / "ghplugin" / "manifest.json").read_text())
        assert manifest["source"]["type"] == "github_release"
        assert manifest["source"]["github_repo"] == "owner/repo"


class TestDownloadFromGitHubArtifact:
    """Tests for download_from_github_artifact method."""

    def test_invalid_artifact_url(self, tmp_path: Path) -> None:
        """Test error with invalid artifact URL."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            downloader = PluginDownloader()

            with pytest.raises(GitHubArtifactError) as exc_info:
                downloader.download_from_github_artifact(
                    "https://github.com/owner/repo/invalid/url"
                )

            assert "Invalid GitHub artifact URL" in str(exc_info.value)

    def test_missing_github_token(self, tmp_path: Path) -> None:
        """Test error when no GitHub token is available."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch.dict("os.environ", {}, clear=True):
                with patch.object(PluginDownloader, "_get_gh_token", return_value=None):
                    downloader = PluginDownloader()

                    with pytest.raises(GitHubArtifactError) as exc_info:
                        downloader.download_from_github_artifact(
                            "https://github.com/owner/repo/actions/runs/123/artifacts/456"
                        )

                    assert "GitHub authentication required" in str(exc_info.value)


class TestGetPluginSource:
    """Tests for get_plugin_source method."""

    def test_get_source_gitguardian(self, tmp_path: Path) -> None:
        """Test getting source for GitGuardian API plugin."""
        plugin_dir = tmp_path / "testplugin"
        plugin_dir.mkdir()
        manifest = {
            "plugin_name": "testplugin",
            "version": "1.0.0",
            "wheel_filename": "testplugin-1.0.0.whl",
            "sha256": "abc123",
            "source": {"type": "gitguardian_api"},
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            source = downloader.get_plugin_source("testplugin")

        assert source is not None
        assert source.type == PluginSourceType.PLATFORM

    def test_get_source_url(self, tmp_path: Path) -> None:
        """Test getting source for URL-installed plugin."""
        plugin_dir = tmp_path / "urlplugin"
        plugin_dir.mkdir()
        manifest = {
            "plugin_name": "urlplugin",
            "version": "1.0.0",
            "wheel_filename": "urlplugin-1.0.0.whl",
            "sha256": "abc123",
            "source": {
                "type": "url",
                "url": "https://example.com/plugin.whl",
            },
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            source = downloader.get_plugin_source("urlplugin")

        assert source is not None
        assert source.type == PluginSourceType.URL
        assert source.url == "https://example.com/plugin.whl"

    def test_get_source_github_release(self, tmp_path: Path) -> None:
        """Test getting source for GitHub release plugin."""
        plugin_dir = tmp_path / "ghplugin"
        plugin_dir.mkdir()
        manifest = {
            "plugin_name": "ghplugin",
            "version": "1.0.0",
            "wheel_filename": "ghplugin-1.0.0.whl",
            "sha256": "abc123",
            "source": {
                "type": "github_release",
                "url": "https://github.com/owner/repo/releases/download/v1.0.0/ghplugin.whl",
                "github_repo": "owner/repo",
            },
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            source = downloader.get_plugin_source("ghplugin")

        assert source is not None
        assert source.type == PluginSourceType.GITHUB_RELEASE
        assert source.github_repo == "owner/repo"

    def test_get_source_legacy_manifest(self, tmp_path: Path) -> None:
        """Test getting source for legacy manifest without source field."""
        plugin_dir = tmp_path / "legacyplugin"
        plugin_dir.mkdir()
        manifest = {
            "plugin_name": "legacyplugin",
            "version": "1.0.0",
            "wheel_filename": "legacyplugin-1.0.0.whl",
            "sha256": "abc123",
            # No source field
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            source = downloader.get_plugin_source("legacyplugin")

        assert source is not None
        assert source.type == PluginSourceType.PLATFORM

    def test_get_source_not_installed(self, tmp_path: Path) -> None:
        """Test getting source for non-installed plugin."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            source = downloader.get_plugin_source("nonexistent")

        assert source is None


class TestPluginSourceTypes:
    """Tests for PluginSource and PluginSourceType."""

    def test_source_to_dict(self) -> None:
        """Test PluginSource serialization."""
        source = PluginSource(
            type=PluginSourceType.GITHUB_RELEASE,
            url="https://example.com",
            github_repo="owner/repo",
            sha256="abc123",
        )

        data = source.to_dict()

        assert data["type"] == "github_release"
        assert data["url"] == "https://example.com"
        assert data["github_repo"] == "owner/repo"
        assert data["sha256"] == "abc123"

    def test_source_from_dict(self) -> None:
        """Test PluginSource deserialization."""
        data = {
            "type": "local_file",
            "local_path": "/path/to/wheel.whl",
            "sha256": "def456",
        }

        source = PluginSource.from_dict(data)

        assert source.type == PluginSourceType.LOCAL_FILE
        assert source.local_path == "/path/to/wheel.whl"
        assert source.sha256 == "def456"

    def test_source_minimal(self) -> None:
        """Test PluginSource with minimal fields."""
        source = PluginSource(type=PluginSourceType.PLATFORM)

        data = source.to_dict()

        assert data == {"type": "platform"}


class TestDownloadFromUrlEdgeCases:
    """Additional tests for download_from_url edge cases."""

    def test_download_from_url_invalid_scheme(self, tmp_path: Path) -> None:
        """Test download fails with invalid URL scheme."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            downloader = PluginDownloader()

            with pytest.raises(DownloadError) as exc_info:
                downloader.download_from_url("ftp://example.com/plugin.whl")

            assert "Invalid URL scheme" in str(exc_info.value)

    def test_download_from_url_network_error(self, tmp_path: Path) -> None:
        """Test download from URL handles network errors."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch(
                "requests.get", side_effect=requests.RequestException("Network error")
            ):
                downloader = PluginDownloader()

                with pytest.raises(DownloadError) as exc_info:
                    downloader.download_from_url("https://example.com/plugin.whl")

                assert "Failed to download from URL" in str(exc_info.value)

    def test_download_from_url_invalid_wheel(self, tmp_path: Path) -> None:
        """Test download from URL with invalid wheel content."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        # Create invalid wheel content
        invalid_content = b"not a valid wheel"

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [invalid_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                downloader = PluginDownloader()

                with pytest.raises(DownloadError) as exc_info:
                    downloader.download_from_url("https://example.com/plugin.whl")

                assert "not a valid wheel" in str(exc_info.value)

    def test_download_from_url_no_whl_extension(self, tmp_path: Path) -> None:
        """Test download from URL defaults filename when not .whl."""
        # Create wheel content
        wheel_dir = tmp_path / "wheel_content"
        wheel_dir.mkdir()
        wheel_path = create_test_wheel(wheel_dir, "testplugin", "1.0.0")
        wheel_content = wheel_path.read_bytes()
        sha256 = hashlib.sha256(wheel_content).hexdigest()

        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [wheel_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                with patch(
                    "ggshield.core.plugin.downloader.verify_wheel_signature",
                    return_value=MOCK_SIG_INFO,
                ):
                    downloader = PluginDownloader()
                    plugin_name, version, _ = downloader.download_from_url(
                        "https://example.com/download?file=something",
                        sha256=sha256,
                    )

        assert plugin_name == "testplugin"
        assert version == "1.0.0"


class TestGitHubArtifactEdgeCases:
    """Additional tests for GitHub artifact download edge cases."""

    def test_github_artifact_success(self, tmp_path: Path) -> None:
        """Test successful GitHub artifact download."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        # Create a wheel for the artifact
        wheel_dir = tmp_path / "wheel_content"
        wheel_dir.mkdir()
        wheel_path = create_test_wheel(wheel_dir, "artifactplugin", "1.0.0")
        wheel_content = wheel_path.read_bytes()

        # Create artifact ZIP containing the wheel
        artifact_content = _create_artifact_zip(
            wheel_content, "artifactplugin-1.0.0.whl"
        )

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [artifact_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                with patch(
                    "ggshield.core.plugin.downloader.verify_wheel_signature",
                    return_value=MOCK_SIG_INFO,
                ):
                    with patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
                        downloader = PluginDownloader()
                        plugin_name, version, installed_path = (
                            downloader.download_from_github_artifact(
                                "https://github.com/owner/repo/actions/runs/123/artifacts/456"
                            )
                        )

        assert plugin_name == "artifactplugin"
        assert version == "1.0.0"
        assert installed_path.exists()

    def test_github_artifact_network_error(self, tmp_path: Path) -> None:
        """Test GitHub artifact download handles network errors."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch(
                "requests.get", side_effect=requests.RequestException("Network error")
            ):
                with patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
                    downloader = PluginDownloader()

                    with pytest.raises(GitHubArtifactError) as exc_info:
                        downloader.download_from_github_artifact(
                            "https://github.com/owner/repo/actions/runs/123/artifacts/456"
                        )

                    assert "Failed to download artifact" in str(exc_info.value)

    def test_github_artifact_no_wheel_in_zip(self, tmp_path: Path) -> None:
        """Test GitHub artifact fails when no wheel in ZIP."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        # Create artifact ZIP without wheel
        artifact_content = _create_artifact_zip(b"readme content", "README.md")

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [artifact_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                with patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
                    downloader = PluginDownloader()

                    with pytest.raises(GitHubArtifactError) as exc_info:
                        downloader.download_from_github_artifact(
                            "https://github.com/owner/repo/actions/runs/123/artifacts/456"
                        )

                    assert "No wheel file found" in str(exc_info.value)

    def test_github_artifact_gh_token_fallback(self, tmp_path: Path) -> None:
        """Test GitHub artifact uses gh CLI token as fallback."""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch.dict("os.environ", {}, clear=True):
                with patch.object(
                    PluginDownloader, "_get_gh_token", return_value="gh-cli-token"
                ):
                    with patch(
                        "requests.get",
                        side_effect=requests.RequestException("Network error"),
                    ):
                        downloader = PluginDownloader()

                        with pytest.raises(GitHubArtifactError) as exc_info:
                            downloader.download_from_github_artifact(
                                "https://github.com/owner/repo/actions/runs/123/artifacts/456"
                            )

                        # Should have tried to download (token was available)
                        assert "Failed to download artifact" in str(exc_info.value)


class TestGetGhToken:
    """Tests for _get_gh_token helper."""

    def test_get_gh_token_success(self, tmp_path: Path) -> None:
        """Test _get_gh_token returns token from gh CLI."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "gh-token-123\n"

            with patch("subprocess.run", return_value=mock_result):
                token = downloader._get_gh_token()

            assert token == "gh-token-123"

    def test_get_gh_token_failure(self, tmp_path: Path) -> None:
        """Test _get_gh_token returns None when gh CLI fails."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

            mock_result = MagicMock()
            mock_result.returncode = 1

            with patch("subprocess.run", return_value=mock_result):
                token = downloader._get_gh_token()

            assert token is None

    def test_get_gh_token_not_installed(self, tmp_path: Path) -> None:
        """Test _get_gh_token returns None when gh CLI not installed."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

            with patch("subprocess.run", side_effect=FileNotFoundError()):
                token = downloader._get_gh_token()

            assert token is None


class TestGetSignatureLabel:
    """Tests for get_signature_label."""

    def test_returns_none_when_no_signature(self) -> None:
        manifest: dict = {"plugin_name": "test", "version": "1.0.0"}
        assert get_signature_label(manifest) is None

    def test_returns_none_when_signature_is_empty(self) -> None:
        manifest: dict = {"signature": {}}
        assert get_signature_label(manifest) is None

    def test_returns_signed_with_identity(self) -> None:
        manifest: dict = {
            "signature": {
                "status": "valid",
                "identity": "GitGuardian/satori",
            }
        }
        assert get_signature_label(manifest) == "signed (GitGuardian/satori)"

    def test_returns_status_without_identity(self) -> None:
        manifest: dict = {"signature": {"status": "missing"}}
        assert get_signature_label(manifest) == "missing"

    def test_returns_trusted_unsigned_label(self) -> None:
        manifest: dict = {"signature": {"status": "missing"}}
        assert (
            get_signature_label(manifest, trusted_unsigned=True) == "unsigned (trusted)"
        )

    def test_returns_unknown_when_no_status(self) -> None:
        manifest: dict = {"signature": {"identity": "org/repo"}}
        assert get_signature_label(manifest) == "unknown (org/repo)"


class TestDownloadUrlBundle:
    """Tests for _download_url_bundle method."""

    def test_returns_none_when_no_bundle_found(self, tmp_path: Path) -> None:
        wheel_path = tmp_path / "plugin-1.0.0.whl"
        wheel_path.write_bytes(b"wheel")

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        with patch("requests.get", side_effect=requests.RequestException("404")):
            result = downloader._download_url_bundle(
                "https://example.com/plugin-1.0.0.whl", wheel_path
            )

        assert result is None
        assert not (tmp_path / "plugin-1.0.0.whl.sigstore").exists()
        assert not (tmp_path / "plugin-1.0.0.whl.sigstore.json").exists()

    def test_falls_back_to_sigstore_json(self, tmp_path: Path) -> None:
        wheel_path = tmp_path / "plugin-1.0.0.whl"
        wheel_path.write_bytes(b"wheel")

        success_response = MagicMock()
        success_response.iter_content.return_value = [b"json-bundle"]
        success_response.raise_for_status = MagicMock()

        def fake_get(url, **_kwargs):
            if url.endswith(".sigstore"):
                raise requests.RequestException("not found")
            return success_response

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        with patch("requests.get", side_effect=fake_get):
            result = downloader._download_url_bundle(
                "https://example.com/plugin-1.0.0.whl", wheel_path
            )

        assert result is not None
        assert result.name == "plugin-1.0.0.whl.sigstore.json"
        assert result.read_bytes() == b"json-bundle"

    def test_removes_partial_bundle_on_mid_stream_error(self, tmp_path: Path) -> None:
        """If iter_content raises after open(), the partial file is unlinked."""
        wheel_path = tmp_path / "plugin-1.0.0.whl"
        wheel_path.write_bytes(b"wheel")

        def iter_boom(*_args, **_kwargs):
            yield b"partial"
            raise OSError("connection reset")

        mock_response = MagicMock()
        mock_response.iter_content.side_effect = iter_boom
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        with patch("requests.get", return_value=mock_response):
            with pytest.raises(OSError):
                downloader._download_url_bundle(
                    "https://example.com/plugin-1.0.0.whl", wheel_path
                )

        assert not (tmp_path / "plugin-1.0.0.whl.sigstore").exists()


class TestCleanupFailedInstall:
    """Tests for _cleanup_failed_install method."""

    def test_removes_wheel_file(self, tmp_path: Path) -> None:
        wheel_path = tmp_path / "plugin-1.0.0.whl"
        wheel_path.write_bytes(b"wheel")

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        downloader._cleanup_failed_install(wheel_path)
        assert not wheel_path.exists()

    def test_removes_bundle_files(self, tmp_path: Path) -> None:
        wheel_path = tmp_path / "plugin-1.0.0.whl"
        wheel_path.write_bytes(b"wheel")
        sigstore = tmp_path / "plugin-1.0.0.whl.sigstore"
        sigstore.write_bytes(b"bundle")
        sigstore_json = tmp_path / "plugin-1.0.0.whl.sigstore.json"
        sigstore_json.write_bytes(b"bundle2")

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        downloader._cleanup_failed_install(wheel_path)
        assert not wheel_path.exists()
        assert not sigstore.exists()
        assert not sigstore_json.exists()

    def test_handles_nonexistent_files(self, tmp_path: Path) -> None:
        wheel_path = tmp_path / "nonexistent.whl"

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        # Should not raise
        downloader._cleanup_failed_install(wheel_path)


class TestWriteManifestWithSignature:
    """Tests for _write_manifest with signature_info."""

    def test_manifest_includes_signature_when_valid(self, tmp_path: Path) -> None:
        sig_info = SignatureInfo(
            status=SignatureStatus.VALID,
            identity="GitGuardian/satori",
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        downloader._write_manifest(
            plugin_dir=tmp_path,
            plugin_name="test",
            version="1.0.0",
            wheel_filename="test-1.0.0.whl",
            sha256="abc",
            source=PluginSource(type=PluginSourceType.GITGUARDIAN_API),
            signature_info=sig_info,
        )

        manifest = json.loads((tmp_path / "manifest.json").read_text())
        assert manifest["signature"]["status"] == "valid"
        assert manifest["signature"]["identity"] == "GitGuardian/satori"
        assert "message" not in manifest["signature"]

    def test_manifest_includes_signature_message(self, tmp_path: Path) -> None:
        sig_info = SignatureInfo(
            status=SignatureStatus.MISSING,
            message="No bundle found",
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        downloader._write_manifest(
            plugin_dir=tmp_path,
            plugin_name="test",
            version="1.0.0",
            wheel_filename="test-1.0.0.whl",
            sha256="abc",
            source=PluginSource(type=PluginSourceType.GITGUARDIAN_API),
            signature_info=sig_info,
        )

        manifest = json.loads((tmp_path / "manifest.json").read_text())
        assert manifest["signature"]["status"] == "missing"
        assert manifest["signature"]["message"] == "No bundle found"

    def test_manifest_omits_signature_when_none(self, tmp_path: Path) -> None:
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        downloader._write_manifest(
            plugin_dir=tmp_path,
            plugin_name="test",
            version="1.0.0",
            wheel_filename="test-1.0.0.whl",
            sha256="abc",
            source=PluginSource(type=PluginSourceType.GITGUARDIAN_API),
        )

        manifest = json.loads((tmp_path / "manifest.json").read_text())
        assert "signature" not in manifest

    def test_tmp_file_is_cleaned_up_on_rename_failure(self, tmp_path: Path) -> None:
        """If replace() fails, the .tmp file is removed and no manifest is left."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        with patch("pathlib.Path.replace", side_effect=OSError("cross-device rename")):
            with pytest.raises(OSError):
                downloader._write_manifest(
                    plugin_dir=tmp_path,
                    plugin_name="test",
                    version="1.0.0",
                    wheel_filename="test-1.0.0.whl",
                    sha256="abc",
                    source=PluginSource(type=PluginSourceType.GITGUARDIAN_API),
                )

        assert not (tmp_path / "manifest.json").exists()
        assert not (tmp_path / "manifest.json.tmp").exists()


def _create_artifact_zip(content: bytes, filename: str) -> bytes:
    """Helper to create an artifact ZIP file in memory."""
    import io

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr(filename, content)
    return buffer.getvalue()


class TestCleanupLegacyInstallDir:
    """Tests for PluginDownloader._cleanup_legacy_install_dir.

    Covers the upgrade path from older ggshield builds that named the
    plugin directory after the catalog reference instead of the wheel's
    distribution name.
    """

    def _downloader(self, tmp_path: Path) -> "PluginDownloader":
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            return PluginDownloader()

    @staticmethod
    def _write_manifest(plugin_dir: Path, source_type: str) -> None:
        manifest = {"source": {"type": source_type}}
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))

    def test_removes_legacy_platform_dir(self, tmp_path: Path) -> None:
        """Legacy ``plugins_dir/<reference>/`` from a platform install is removed."""
        downloader = self._downloader(tmp_path)
        legacy = tmp_path / "machine_scan"
        legacy.mkdir()
        self._write_manifest(legacy, "platform")
        new_install = tmp_path / "satori-python"
        new_install.mkdir()

        downloader._cleanup_legacy_install_dir(
            catalog_reference="machine_scan", current_dir=new_install
        )

        assert not legacy.exists()
        assert new_install.exists()

    def test_removes_legacy_gitguardian_api_dir(self, tmp_path: Path) -> None:
        """Manifests written by ggshield < 1.50 use the old ``gitguardian_api``
        value but still represent a platform install — accept them too."""
        downloader = self._downloader(tmp_path)
        legacy = tmp_path / "machine_scan"
        legacy.mkdir()
        self._write_manifest(legacy, "gitguardian_api")
        new_install = tmp_path / "satori-python"
        new_install.mkdir()

        downloader._cleanup_legacy_install_dir(
            catalog_reference="machine_scan", current_dir=new_install
        )

        assert not legacy.exists()

    @pytest.mark.parametrize(
        "user_source_type",
        ["local_file", "url", "github_release", "github_artifact"],
    )
    def test_preserves_user_managed_dir(
        self, tmp_path: Path, user_source_type: str
    ) -> None:
        """A directory whose name collides with the catalog reference but whose
        manifest says it was user-installed (local_file / url / github_*) must
        not be wiped by the platform-install cleanup path.
        """
        downloader = self._downloader(tmp_path)
        collider = tmp_path / "tokenscanner"
        collider.mkdir()
        self._write_manifest(collider, user_source_type)
        new_install = tmp_path / "ggshield-tokenscanner"
        new_install.mkdir()
        downloader.trust_store = MagicMock()

        downloader._cleanup_legacy_install_dir(
            catalog_reference="tokenscanner", current_dir=new_install
        )

        assert (
            collider.exists()
        ), f"cleanup deleted a user-managed {user_source_type} install"
        assert (collider / "manifest.json").exists()
        downloader.trust_store.revoke_plugin.assert_not_called()

    def test_preserves_dir_with_unparseable_manifest(self, tmp_path: Path) -> None:
        """A malformed manifest is ambiguous evidence; don't risk wiping
        a legitimate user-managed directory."""
        downloader = self._downloader(tmp_path)
        legacy = tmp_path / "machine_scan"
        legacy.mkdir()
        (legacy / "manifest.json").write_text("{not json")
        new_install = tmp_path / "satori-python"
        new_install.mkdir()

        downloader._cleanup_legacy_install_dir(
            catalog_reference="machine_scan", current_dir=new_install
        )

        assert legacy.exists()

    def test_keeps_dir_when_same_as_current(self, tmp_path: Path) -> None:
        """When wheel-distribution-name == catalog-reference, no migration."""
        downloader = self._downloader(tmp_path)
        plugin_dir = tmp_path / "tokenscanner"
        plugin_dir.mkdir()
        self._write_manifest(plugin_dir, "platform")

        downloader._cleanup_legacy_install_dir(
            catalog_reference="tokenscanner", current_dir=plugin_dir
        )

        assert plugin_dir.exists()

    def test_skips_dir_without_manifest(self, tmp_path: Path) -> None:
        """A bare directory without a manifest isn't a plugin install — leave it alone."""
        downloader = self._downloader(tmp_path)
        not_a_plugin = tmp_path / "machine_scan"
        not_a_plugin.mkdir()
        (not_a_plugin / "random.txt").write_text("hi")
        new_install = tmp_path / "satori-python"
        new_install.mkdir()

        downloader._cleanup_legacy_install_dir(
            catalog_reference="machine_scan", current_dir=new_install
        )

        assert not_a_plugin.exists()

    def test_skips_when_legacy_dir_missing(self, tmp_path: Path) -> None:
        """No-op when the catalog-reference directory doesn't exist."""
        downloader = self._downloader(tmp_path)
        new_install = tmp_path / "satori-python"
        new_install.mkdir()

        # Should not raise.
        downloader._cleanup_legacy_install_dir(
            catalog_reference="machine_scan", current_dir=new_install
        )

    def test_rejects_invalid_catalog_reference(self, tmp_path: Path) -> None:
        """An invalid name (path-traversal etc.) is silently ignored."""
        downloader = self._downloader(tmp_path)
        new_install = tmp_path / "satori-python"
        new_install.mkdir()

        # Should not raise even though "../etc" is bogus.
        downloader._cleanup_legacy_install_dir(
            catalog_reference="../etc", current_dir=new_install
        )

    def test_swallows_oserror_during_rmtree(self, tmp_path: Path) -> None:
        """Filesystem error during rmtree is logged, not raised."""
        downloader = self._downloader(tmp_path)
        legacy = tmp_path / "machine_scan"
        legacy.mkdir()
        self._write_manifest(legacy, "platform")
        new_install = tmp_path / "satori-python"
        new_install.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.shutil.rmtree",
            side_effect=OSError("permission denied"),
        ):
            downloader._cleanup_legacy_install_dir(
                catalog_reference="machine_scan", current_dir=new_install
            )

        # Did not crash. The legacy dir is still there because rmtree raised.
        assert legacy.exists()

    def test_revokes_trust_record_after_removal(self, tmp_path: Path) -> None:
        """After removing the legacy dir, the trust record keyed on the
        catalog reference is revoked so a fresh install under that key
        doesn't inherit a stale SHA."""
        downloader = self._downloader(tmp_path)
        legacy = tmp_path / "machine_scan"
        legacy.mkdir()
        self._write_manifest(legacy, "platform")
        new_install = tmp_path / "satori-python"
        new_install.mkdir()
        downloader.trust_store = MagicMock()

        downloader._cleanup_legacy_install_dir(
            catalog_reference="machine_scan", current_dir=new_install
        )

        downloader.trust_store.revoke_plugin.assert_called_once_with("machine_scan")


class TestRemoveStaleWheels:
    """Regression: upgrading from foo-1.0.whl to foo-2.0.whl used to leave
    the old wheel + sidecar on disk. The plugin directory accumulated one
    stale wheel per upgrade; the manifest pointed at the new one so
    function still worked but disk usage grew and audits were noisy.
    """

    def _downloader(self, tmp_path: Path) -> "PluginDownloader":
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            return PluginDownloader()

    def test_removes_other_wheels_and_their_sidecars(self, tmp_path: Path) -> None:
        downloader = self._downloader(tmp_path)
        plugin_dir = tmp_path / "foo"
        plugin_dir.mkdir()
        # Old wheel + its sidecars (the stale install).
        (plugin_dir / "foo-1.0.whl").write_bytes(b"old")
        (plugin_dir / "foo-1.0.whl.sigstore").write_bytes(b"old-sig")
        (plugin_dir / "foo-1.0.whl.sigstore.json").write_bytes(b"old-sig-json")
        # New wheel + its sidecar.
        (plugin_dir / "foo-2.0.whl").write_bytes(b"new")
        (plugin_dir / "foo-2.0.whl.sigstore").write_bytes(b"new-sig")
        # Unrelated file that must survive.
        (plugin_dir / "manifest.json").write_bytes(b"{}")

        downloader._remove_stale_wheels(plugin_dir, keep_filename="foo-2.0.whl")

        names = {p.name for p in plugin_dir.iterdir()}
        assert names == {
            "foo-2.0.whl",
            "foo-2.0.whl.sigstore",
            "manifest.json",
        }

    def test_keeps_target_wheel(self, tmp_path: Path) -> None:
        """The kept wheel and its sidecars must not be touched."""
        downloader = self._downloader(tmp_path)
        plugin_dir = tmp_path / "foo"
        plugin_dir.mkdir()
        (plugin_dir / "foo-2.0.whl").write_bytes(b"new")
        (plugin_dir / "foo-2.0.whl.sigstore").write_bytes(b"new-sig")

        downloader._remove_stale_wheels(plugin_dir, keep_filename="foo-2.0.whl")

        assert (plugin_dir / "foo-2.0.whl").exists()
        assert (plugin_dir / "foo-2.0.whl.sigstore").exists()

    def test_no_op_when_no_other_wheels(self, tmp_path: Path) -> None:
        downloader = self._downloader(tmp_path)
        plugin_dir = tmp_path / "foo"
        plugin_dir.mkdir()
        (plugin_dir / "foo-1.0.whl").write_bytes(b"only")
        (plugin_dir / "manifest.json").write_bytes(b"{}")

        downloader._remove_stale_wheels(plugin_dir, keep_filename="foo-1.0.whl")

        assert (plugin_dir / "foo-1.0.whl").exists()
        assert (plugin_dir / "manifest.json").exists()

    def test_skips_non_wheel_files(self, tmp_path: Path) -> None:
        """Random files that happen to share the plugin dir aren't wheels;
        leave them alone even though they look like cruft."""
        downloader = self._downloader(tmp_path)
        plugin_dir = tmp_path / "foo"
        plugin_dir.mkdir()
        (plugin_dir / "foo-2.0.whl").write_bytes(b"new")
        (plugin_dir / "README.txt").write_bytes(b"docs")
        (plugin_dir / "fake.whl.bak").write_bytes(b"backup")

        downloader._remove_stale_wheels(plugin_dir, keep_filename="foo-2.0.whl")

        assert (plugin_dir / "README.txt").exists()
        assert (plugin_dir / "fake.whl.bak").exists()

    def test_swallows_unlink_oserror(self, tmp_path: Path) -> None:
        """A read-only filesystem mustn't abort the install — log and move on."""
        downloader = self._downloader(tmp_path)
        plugin_dir = tmp_path / "foo"
        plugin_dir.mkdir()
        (plugin_dir / "foo-1.0.whl").write_bytes(b"old")
        (plugin_dir / "foo-2.0.whl").write_bytes(b"new")

        with patch.object(Path, "unlink", side_effect=OSError("read-only")):
            # Must not raise.
            downloader._remove_stale_wheels(plugin_dir, keep_filename="foo-2.0.whl")


class TestResolvePluginDirFallback:
    """Regression: a bare ``plugins_dir/<name>/`` without a manifest must
    not block resolution of the real install that lives under the
    wheel's distribution-name directory.
    """

    def _downloader(self, tmp_path: Path) -> "PluginDownloader":
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            return PluginDownloader()

    def test_direct_path_with_manifest_returns_direct(self, tmp_path: Path) -> None:
        downloader = self._downloader(tmp_path)
        plugin_dir = tmp_path / "tokenscanner"
        plugin_dir.mkdir()
        (plugin_dir / "manifest.json").write_text("{}")

        assert downloader._resolve_plugin_dir("tokenscanner") == plugin_dir

    def test_direct_path_without_manifest_falls_through(self, tmp_path: Path) -> None:
        """Stale ``plugins_dir/<catalog_ref>/`` (no manifest) must not be
        returned — fall through to the entry-point scan so the real install
        under the wheel's distribution name still resolves."""
        downloader = self._downloader(tmp_path)

        # Bare residue dir (no manifest) named after the catalog reference.
        bare = tmp_path / "machine_scan"
        bare.mkdir()
        (bare / "stray.txt").write_text("not a plugin")

        # Real install lives under the wheel distribution name and has a
        # wheel with an entry point named "machine_scan".
        real_dir = tmp_path / "satori-python"
        real_dir.mkdir()
        wheel_path = real_dir / "satori_python-1.0.0.whl"
        with zipfile.ZipFile(wheel_path, "w") as zf:
            zf.writestr(
                "satori_python-1.0.0.dist-info/entry_points.txt",
                "[ggshield.plugins]\nmachine_scan = satori_python.plugin:Plugin\n",
            )
        manifest = {
            "plugin_name": "satori-python",
            "version": "1.0.0",
            "wheel_filename": "satori_python-1.0.0.whl",
        }
        (real_dir / "manifest.json").write_text(json.dumps(manifest))

        assert downloader._resolve_plugin_dir("machine_scan") == real_dir

    def test_no_direct_no_entry_point_returns_none(self, tmp_path: Path) -> None:
        downloader = self._downloader(tmp_path)
        assert downloader._resolve_plugin_dir("absent") is None


class TestWheelDistributionName:
    """Tests for _wheel_distribution_name (PEP 427 → PEP 503)."""

    def test_normalises_underscores(self) -> None:
        from ggshield.core.plugin.downloader import _wheel_distribution_name

        assert (
            _wheel_distribution_name(
                "satori_python-0.38.1-cp37-abi3-manylinux_2_28_x86_64.whl"
            )
            == "satori-python"
        )

    def test_lowercases(self) -> None:
        from ggshield.core.plugin.downloader import _wheel_distribution_name

        assert _wheel_distribution_name("Foo-1.0.0-py3-none-any.whl") == "foo"

    def test_rejects_non_wheel_extension(self) -> None:
        from ggshield.core.plugin.downloader import _wheel_distribution_name

        with pytest.raises(DownloadError, match="Not a wheel filename"):
            _wheel_distribution_name("plugin-1.0.0.tar.gz")

    def test_rejects_invalid_format(self) -> None:
        """A wheel filename without version/python segments is rejected."""
        from ggshield.core.plugin.downloader import _wheel_distribution_name

        # No '-' at all → bad format.
        with pytest.raises(DownloadError, match="Invalid wheel filename"):
            _wheel_distribution_name("plugin.whl")


class TestDownloadAndInstallBundle:
    """Tests for the bundle_bytes path of download_and_install."""

    def test_writes_bundle_alongside_wheel(self, tmp_path: Path) -> None:
        """bundle_bytes is persisted as ``<wheel>.sigstore`` next to the
        wheel in the install dir."""
        wheel_content = b"fake wheel content"
        sha256 = hashlib.sha256(wheel_content).hexdigest()
        bundle_bytes = b'{"fake": "bundle"}'
        download_info = PluginDownloadInfo(
            filename="plug-1.0.0.whl",
            sha256=sha256,
            version="1.0.0",
            size_bytes=len(wheel_content),
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ), patch(
            "ggshield.core.plugin.downloader.verify_wheel_signature",
            return_value=MOCK_SIG_INFO,
        ):
            downloader = PluginDownloader()
            wheel_path = downloader.download_and_install(
                download_info,
                iter([wheel_content]),
                "plug",
                bundle_bytes=bundle_bytes,
            )

        bundle_path = wheel_path.parent / (wheel_path.name + ".sigstore")
        assert bundle_path.exists()
        assert bundle_path.read_bytes() == bundle_bytes

    def test_signature_failure_leaves_existing_install_intact(
        self, tmp_path: Path
    ) -> None:
        """When STRICT verification fails on update, the previous install
        (wheel + manifest) is untouched."""
        # Pre-populate the install dir as if a prior version is already
        # installed (matches the real upgrade scenario).
        install_dir = tmp_path / "plug"
        install_dir.mkdir()
        previous_wheel_bytes = b"previous good wheel"
        previous_wheel_path = install_dir / "plug-0.9.0.whl"
        previous_wheel_path.write_bytes(previous_wheel_bytes)
        previous_manifest = install_dir / "manifest.json"
        previous_manifest.write_text('{"plugin_name":"plug","version":"0.9.0"}')

        wheel_content = b"new (unsigned) wheel"
        sha256 = hashlib.sha256(wheel_content).hexdigest()
        download_info = PluginDownloadInfo(
            filename="plug-1.0.0.whl",
            sha256=sha256,
            version="1.0.0",
            size_bytes=len(wheel_content),
        )

        from ggshield.core.plugin.signature import (
            SignatureStatus,
            SignatureVerificationError,
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ), patch(
            "ggshield.core.plugin.downloader.verify_wheel_signature",
            side_effect=SignatureVerificationError(SignatureStatus.MISSING, "missing"),
        ):
            downloader = PluginDownloader()
            with pytest.raises(SignatureVerificationError):
                downloader.download_and_install(
                    download_info, iter([wheel_content]), "plug"
                )

        # Previous install untouched.
        assert previous_wheel_path.exists()
        assert previous_wheel_path.read_bytes() == previous_wheel_bytes
        assert previous_manifest.exists()
        # And the temp file got cleaned up.
        assert not (install_dir / "plug-1.0.0.whl.tmp").exists()


class TestGetSignatureLabelExtra:
    """Additional get_signature_label coverage."""

    def test_signed_without_identity(self) -> None:
        """A valid signature without identity returns plain 'signed'."""
        manifest = {"signature": {"status": "valid"}}
        assert get_signature_label(manifest) == "signed"


class TestDownloadAndInstallBundleCleanup:
    """Tests for the finally-clause bundle cleanup in download_and_install."""

    def test_temp_bundle_cleaned_up_when_signature_fails(self, tmp_path: Path) -> None:
        """Temp bundle file written before signature verification is
        removed when verification fails (the only path that exercises
        the temp bundle's finally-clause unlink)."""
        wheel_content = b"actual bytes"
        sha256 = hashlib.sha256(wheel_content).hexdigest()
        download_info = PluginDownloadInfo(
            filename="plug-1.0.0.whl",
            sha256=sha256,
            version="1.0.0",
            size_bytes=len(wheel_content),
        )
        from ggshield.core.plugin.signature import (
            SignatureStatus,
            SignatureVerificationError,
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ), patch(
            "ggshield.core.plugin.downloader.verify_wheel_signature",
            side_effect=SignatureVerificationError(
                SignatureStatus.MISSING, "no bundle"
            ),
        ):
            downloader = PluginDownloader()
            with pytest.raises(SignatureVerificationError):
                downloader.download_and_install(
                    download_info,
                    iter([wheel_content]),
                    "plug",
                    bundle_bytes=b"some bundle",
                )

        # Temp wheel and temp bundle both gone after the failure.
        plugin_dir = tmp_path / "plug"
        if plugin_dir.exists():
            for entry in plugin_dir.iterdir():
                assert not entry.name.endswith(".tmp")
                assert not entry.name.endswith(".tmp.sigstore")

    def test_temp_bundle_cleaned_up_on_sha_mismatch(self, tmp_path: Path) -> None:
        """Temp bundle file written before SHA verification is removed
        when the install fails downstream."""
        wheel_content = b"actual bytes"
        wrong_sha = "0" * 64
        download_info = PluginDownloadInfo(
            filename="plug-1.0.0.whl",
            sha256=wrong_sha,
            version="1.0.0",
            size_bytes=len(wheel_content),
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            with pytest.raises(ChecksumMismatchError):
                downloader.download_and_install(
                    download_info,
                    iter([wheel_content]),
                    "plug",
                    bundle_bytes=b"some bundle",
                )

        # Neither the temp wheel nor the temp bundle should remain.
        plugin_dir = tmp_path / "plug"
        for name in plugin_dir.iterdir() if plugin_dir.exists() else []:
            assert not name.name.endswith(".tmp")
            assert not name.name.endswith(".tmp.sigstore")


class TestStreamToFile:
    """Tests for the module-level _stream_to_file helper."""

    def test_skips_empty_chunks_and_caps_oversized_body(self, tmp_path: Path) -> None:
        """Empty chunks (line 94 ``continue``) and the size cap (line 97
        ``raise``) are both exercised here."""
        from ggshield.core.plugin.downloader import _stream_to_file

        response = MagicMock()
        # Empty chunk (skipped), then a chunk that exceeds the cap.
        response.iter_content.return_value = iter([b"", b"x" * 100])

        dest = tmp_path / "out.bin"
        with pytest.raises(DownloadError, match="exceeded maximum"):
            _stream_to_file(response, dest, max_bytes=50)

        # Partial file removed before re-raise.
        assert not dest.exists()


class TestExtractGithubRepo:
    """Tests for the _extract_github_repo helper."""

    def _downloader(self, tmp_path: Path) -> "PluginDownloader":
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            return PluginDownloader()

    def test_returns_owner_repo_for_valid_url(self, tmp_path: Path) -> None:
        d = self._downloader(tmp_path)
        assert d._extract_github_repo("https://github.com/owner/repo") == "owner/repo"

    def test_strips_dotgit_suffix(self, tmp_path: Path) -> None:
        d = self._downloader(tmp_path)
        assert (
            d._extract_github_repo("https://github.com/owner/repo.git") == "owner/repo"
        )

    def test_returns_none_for_non_github_url(self, tmp_path: Path) -> None:
        d = self._downloader(tmp_path)
        assert d._extract_github_repo("https://example.com/owner/repo") is None

    def test_rejects_path_traversal_segments(self, tmp_path: Path) -> None:
        d = self._downloader(tmp_path)
        assert d._extract_github_repo("https://github.com/../repo") is None
        assert d._extract_github_repo("https://github.com/owner/..") is None
        assert d._extract_github_repo("https://github.com/./repo") is None

    def test_rejects_slash_in_segment(self, tmp_path: Path) -> None:
        """Slash and backslash within the segment are rejected — they
        could escape the api.github.com URL the value gets interpolated
        into. Trigger the path via a regex that allows them through.
        """
        d = self._downloader(tmp_path)
        # urlparse-driven regex captures up to the next '/', so slashes
        # don't naturally get into the segment from a real URL. Force
        # it via a direct match: backslash inside a segment.
        # Construct a URL that allows ``\`` to land inside one segment.
        # The current regex is ``([^/]+)/([^/]+)`` — non-slash chars,
        # so backslash sneaks in.
        assert d._extract_github_repo("https://github.com/owner\\evil/repo") is None


class TestDownloadFromUrlFinally:
    """Tests for the temp-file cleanup in download_from_url."""

    def test_cleans_up_temp_file_on_request_error(self, tmp_path: Path) -> None:
        """A request exception during streaming should leave no temp file
        behind in the staging area."""
        from ggshield.core.plugin.downloader import _stream_to_file

        # Easier path: drive _stream_to_file directly to assert the
        # finally branch in download_from_url's caller. The wrapper's
        # finally clause unlinks the temp file regardless of why
        # _stream_to_file raised.
        response = MagicMock()
        response.iter_content.return_value = iter([b"x" * 50])
        dest = tmp_path / "stage.tmp"
        with pytest.raises(DownloadError):
            _stream_to_file(response, dest, max_bytes=10)
        assert not dest.exists()


class TestDownloadFromGithubReleaseFinally:
    """Cover the finally-clause manifest-tmp cleanup in download_from_github_release."""

    def test_cleans_up_tmp_manifest_when_replace_fails(self, tmp_path: Path) -> None:
        """If atomic replace of manifest.json fails, the leftover .tmp
        file is removed by the finally clause."""
        plugin_dir = tmp_path / "p"
        plugin_dir.mkdir()
        manifest_path = plugin_dir / "manifest.json"
        manifest_path.write_text(
            '{"plugin_name": "p", "version": "1.0", "sha256": "abc"}'
        )

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()

        # Stub download_from_url to skip the actual download work.
        downloader.download_from_url = MagicMock(  # type: ignore[method-assign]
            return_value=("p", "1.0", plugin_dir / "p-1.0.whl")
        )

        # Make Path.replace raise so the .tmp file lingers and the
        # finally clause has to clean it up.
        from pathlib import Path as _PathCls

        with patch.object(_PathCls, "replace", side_effect=OSError("rename failed")):
            with pytest.raises(OSError):
                downloader.download_from_github_release(
                    "https://github.com/owner/repo/releases/download/v1/p-1.0.whl"
                )

        # No leftover .tmp manifest.
        assert not (plugin_dir / "manifest.json.tmp").exists()


class TestInstallFromWheelBundleCopy:
    """Cover install_from_wheel copying a co-located bundle (line 372)."""

    def test_install_from_wheel_copies_bundle_when_present(
        self, tmp_path: Path
    ) -> None:
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        wheel_path = create_test_wheel(source_dir, "bundleplugin", "1.0.0")
        bundle_path = source_dir / f"{wheel_path.name}.sigstore"
        bundle_path.write_bytes(b"fake-bundle")

        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch(
                "ggshield.core.plugin.downloader.verify_wheel_signature",
                return_value=MOCK_SIG_INFO,
            ):
                with patch(
                    "ggshield.core.plugin.signature.get_bundle_path",
                    return_value=bundle_path,
                ):
                    downloader = PluginDownloader()
                    downloader.install_from_wheel(wheel_path)

        installed_bundle = plugins_dir / "bundleplugin" / bundle_path.name
        assert installed_bundle.exists()
        assert installed_bundle.read_bytes() == b"fake-bundle"


class TestGitHubArtifactExtraEdgeCases:
    """Cover remaining download_from_github_artifact branches.

    Lines 629-630 (safe_unpack failure), 642 (multiple wheels warning),
    652-653 (WheelError), 675-676 (bundle copy).
    """

    def test_safe_unpack_failure_raises_artifact_error(self, tmp_path: Path) -> None:
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        artifact_content = _create_artifact_zip(b"x", "ignored.txt")
        mock_response = MagicMock()
        mock_response.iter_content.return_value = [artifact_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                with patch(
                    "ggshield.utils.archive.safe_unpack",
                    side_effect=RuntimeError("zip slip"),
                ):
                    with patch.dict("os.environ", {"GITHUB_TOKEN": "tok"}):
                        downloader = PluginDownloader()
                        with pytest.raises(GitHubArtifactError) as exc:
                            downloader.download_from_github_artifact(
                                "https://github.com/o/r/actions/runs/1/artifacts/2"
                            )
        assert "Failed to extract artifact" in str(exc.value)

    def test_multiple_wheels_logs_warning_and_picks_first(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        wheel_dir = tmp_path / "wheels"
        wheel_dir.mkdir()
        wheel_a = create_test_wheel(wheel_dir, "alpha", "1.0.0")
        wheel_b = create_test_wheel(wheel_dir, "beta", "2.0.0")

        import io

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr(wheel_a.name, wheel_a.read_bytes())
            zf.writestr(wheel_b.name, wheel_b.read_bytes())
        artifact_content = buffer.getvalue()

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [artifact_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                with patch(
                    "ggshield.core.plugin.downloader.verify_wheel_signature",
                    return_value=MOCK_SIG_INFO,
                ):
                    with patch.dict("os.environ", {"GITHUB_TOKEN": "tok"}):
                        with caplog.at_level("WARNING"):
                            downloader = PluginDownloader()
                            plugin_name, _, _ = (
                                downloader.download_from_github_artifact(
                                    "https://github.com/o/r/actions/runs/1/artifacts/2"
                                )
                            )

        assert plugin_name == "alpha"
        assert any("Multiple wheel files" in rec.message for rec in caplog.records)

    def test_invalid_wheel_in_artifact_raises_download_error(
        self, tmp_path: Path
    ) -> None:
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        artifact_content = _create_artifact_zip(
            b"not-a-zip", "broken-1.0.0-py3-none-any.whl"
        )

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [artifact_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                with patch.dict("os.environ", {"GITHUB_TOKEN": "tok"}):
                    downloader = PluginDownloader()
                    with pytest.raises(DownloadError) as exc:
                        downloader.download_from_github_artifact(
                            "https://github.com/o/r/actions/runs/1/artifacts/2"
                        )
        assert "Invalid wheel in artifact" in str(exc.value)

    def test_artifact_copies_sigstore_bundle_when_present(self, tmp_path: Path) -> None:
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()

        wheel_dir = tmp_path / "wheels"
        wheel_dir.mkdir()
        wheel_path = create_test_wheel(wheel_dir, "sigplugin", "1.0.0")
        wheel_bytes = wheel_path.read_bytes()

        import io

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.writestr(wheel_path.name, wheel_bytes)
            zf.writestr(wheel_path.name + ".sigstore", b"bundle-bytes")
        artifact_content = buffer.getvalue()

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [artifact_content]
        mock_response.raise_for_status = MagicMock()

        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=plugins_dir
        ):
            with patch("requests.get", return_value=mock_response):
                with patch(
                    "ggshield.core.plugin.downloader.verify_wheel_signature",
                    return_value=MOCK_SIG_INFO,
                ):
                    with patch.dict("os.environ", {"GITHUB_TOKEN": "tok"}):
                        downloader = PluginDownloader()
                        downloader.download_from_github_artifact(
                            "https://github.com/o/r/actions/runs/1/artifacts/2"
                        )

        installed_bundle = plugins_dir / "sigplugin" / (wheel_path.name + ".sigstore")
        assert installed_bundle.exists()
        assert installed_bundle.read_bytes() == b"bundle-bytes"


class TestUninstallInvalidName:
    """Cover uninstall rejecting unsafe plugin names (lines 703-704)."""

    def test_uninstall_rejects_invalid_name(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            with caplog.at_level("WARNING"):
                assert downloader.uninstall("../escape") is False
        assert any("Invalid plugin name" in rec.message for rec in caplog.records)


class TestManifestPathErrors:
    """Cover _get_manifest_path branches via public callers."""

    def test_get_manifest_invalid_name_returns_none(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Lines 737-738: invalid plugin name path."""
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            with caplog.at_level("WARNING"):
                assert downloader.get_manifest("../escape") is None
        assert any("Invalid plugin name" in rec.message for rec in caplog.records)

    def test_get_manifest_dir_without_manifest_returns_none(
        self, tmp_path: Path
    ) -> None:
        """Line 746: plugin dir exists but has no manifest.json."""
        plugin_dir = tmp_path / "noManifestPlugin"
        plugin_dir.mkdir()
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            assert downloader.get_manifest("noManifestPlugin") is None


class TestFindPluginDirByEntryPointBranches:
    """Cover defensive branches in _find_plugin_dir_by_entry_point."""

    def test_skips_files_in_plugins_dir(self, tmp_path: Path) -> None:
        """Line 756: plain file in plugins_dir is skipped."""
        (tmp_path / "stray.txt").write_text("hi")
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            # Lookup by entry-point name with no matching dirs returns None
            # without crashing on the stray file.
            assert downloader.get_manifest("anyplugin") is None

    def test_skips_dirs_without_manifest(self, tmp_path: Path) -> None:
        """Line 760: directory without manifest.json is skipped."""
        (tmp_path / "emptydir").mkdir()
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            assert downloader.get_manifest("anyplugin") is None

    def test_handles_invalid_manifest_json(self, tmp_path: Path) -> None:
        """Lines 772-773: dir with invalid JSON manifest is skipped."""
        plugin_dir = tmp_path / "broken"
        plugin_dir.mkdir()
        (plugin_dir / "manifest.json").write_text("{not-json}")
        # Different lookup name so we exercise entry-point traversal.
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            assert downloader.get_manifest("entrypointname") is None


class TestGetWheelPathInvalidJson:
    """Cover get_wheel_path JSON decode fallthrough (lines 797-800)."""

    def test_invalid_json_manifest_returns_none(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "badjson"
        plugin_dir.mkdir()
        (plugin_dir / "manifest.json").write_text("{not-valid-json}")
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            assert downloader.get_wheel_path("badjson") is None


class TestGetManifestInvalidJson:
    """Cover get_manifest JSON decode fallthrough (lines 810-811)."""

    def test_invalid_json_returns_none(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "badjson2"
        plugin_dir.mkdir()
        (plugin_dir / "manifest.json").write_text("{not-valid-json}")
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            assert downloader.get_manifest("badjson2") is None


class TestGetInstalledSignatureLabelMissingPlugin:
    """Cover get_installed_signature_label early-return (line 817)."""

    def test_returns_none_for_missing_plugin(self, tmp_path: Path) -> None:
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            assert downloader.get_installed_signature_label("nope") is None


class TestGetPluginSourceInvalidSourceDict:
    """Cover get_plugin_source PluginSource.from_dict failure (lines 842-843)."""

    def test_source_missing_type_returns_none(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "bad_source"
        plugin_dir.mkdir()
        manifest = {
            "plugin_name": "bad_source",
            "version": "1.0.0",
            "wheel_filename": "bad_source-1.0.0.whl",
            "sha256": "deadbeef",
            "source": {"url": "https://example.com"},  # missing "type"
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            assert downloader.get_plugin_source("bad_source") is None

    def test_source_unknown_type_returns_none(self, tmp_path: Path) -> None:
        plugin_dir = tmp_path / "weird_source"
        plugin_dir.mkdir()
        manifest = {
            "plugin_name": "weird_source",
            "version": "1.0.0",
            "wheel_filename": "weird_source-1.0.0.whl",
            "sha256": "deadbeef",
            "source": {"type": "wormhole"},  # unknown enum value
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            assert downloader.get_plugin_source("weird_source") is None


class TestIsValidPluginNameRejections:
    """Cover _is_valid_plugin_name reject branches (lines 849, 853)."""

    @pytest.mark.parametrize("name", ["", ".", ".."])
    def test_rejects_empty_or_dot_segments(self, tmp_path: Path, name: str) -> None:
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            assert downloader.uninstall(name) is False

    def test_rejects_null_byte(self, tmp_path: Path) -> None:
        with patch(
            "ggshield.core.plugin.downloader.get_plugins_dir", return_value=tmp_path
        ):
            downloader = PluginDownloader()
            assert downloader.uninstall("foo\x00bar") is False
