"""Tests for plugin signature verification."""

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from unittest.mock import MagicMock, patch

import pytest

from ggshield.core.plugin.signature import (
    SignatureStatus,
    SignatureVerificationError,
    SignatureVerificationMode,
    TrustedIdentity,
    get_bundle_path,
    verify_wheel_signature,
)


class TestGetBundlePath:
    """Tests for get_bundle_path()."""

    def test_returns_sigstore_extension(self, tmp_path: Path) -> None:
        wheel = tmp_path / "plugin-1.0.0.whl"
        bundle = tmp_path / "plugin-1.0.0.whl.sigstore"
        bundle.write_bytes(b"bundle")
        result = get_bundle_path(wheel)
        assert result == bundle

    def test_returns_sigstore_json_extension(self, tmp_path: Path) -> None:
        wheel = tmp_path / "plugin-1.0.0.whl"
        bundle = tmp_path / "plugin-1.0.0.whl.sigstore.json"
        bundle.write_bytes(b"bundle")
        result = get_bundle_path(wheel)
        assert result == bundle

    def test_prefers_sigstore_over_sigstore_json(self, tmp_path: Path) -> None:
        wheel = tmp_path / "plugin-1.0.0.whl"
        (tmp_path / "plugin-1.0.0.whl.sigstore").write_bytes(b"bundle1")
        (tmp_path / "plugin-1.0.0.whl.sigstore.json").write_bytes(b"bundle2")
        result = get_bundle_path(wheel)
        assert result == tmp_path / "plugin-1.0.0.whl.sigstore"

    def test_returns_none_when_no_bundle(self, tmp_path: Path) -> None:
        wheel = tmp_path / "plugin-1.0.0.whl"
        result = get_bundle_path(wheel)
        assert result is None

    def test_preserves_parent_directory(self, tmp_path: Path) -> None:
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        wheel = subdir / "plugin.whl"
        bundle = subdir / "plugin.whl.sigstore"
        bundle.write_bytes(b"bundle")
        result = get_bundle_path(wheel)
        assert result is not None
        assert result.parent == subdir


class TestSignatureVerificationModeDisabled:
    """Tests for DISABLED mode."""

    def test_returns_skipped(self, tmp_path: Path) -> None:
        wheel = tmp_path / "plugin.whl"
        wheel.write_bytes(b"fake wheel")

        result = verify_wheel_signature(wheel, SignatureVerificationMode.DISABLED)

        assert result.status == SignatureStatus.SKIPPED


class TestMissingBundle:
    """Tests for missing .sigstore bundle."""

    def test_strict_mode_raises(self, tmp_path: Path) -> None:
        wheel = tmp_path / "plugin.whl"
        wheel.write_bytes(b"fake wheel")
        # No .sigstore file

        with pytest.raises(SignatureVerificationError) as exc_info:
            verify_wheel_signature(wheel, SignatureVerificationMode.STRICT)

        assert exc_info.value.status == SignatureStatus.MISSING

    def test_warn_mode_returns_missing(self, tmp_path: Path) -> None:
        wheel = tmp_path / "plugin.whl"
        wheel.write_bytes(b"fake wheel")

        result = verify_wheel_signature(wheel, SignatureVerificationMode.WARN)

        assert result.status == SignatureStatus.MISSING


class TestBundleVerification:
    """Tests for bundle verification with mocked sigstore."""

    def _setup_wheel_and_bundle(self, tmp_path: Path) -> Path:
        """Create a fake wheel and bundle file."""
        wheel = tmp_path / "plugin-1.0.0.whl"
        wheel.write_bytes(b"fake wheel content")
        bundle = tmp_path / "plugin-1.0.0.whl.sigstore"
        bundle.write_bytes(b'{"fake": "bundle"}')
        return wheel

    @staticmethod
    @contextmanager
    def _sigstore_modules(
        mock_verifier_cls: MagicMock,
        mock_bundle_cls: MagicMock,
        mock_all_of_cls: MagicMock,
        mock_oidc_issuer_cls: MagicMock,
        mock_gh_repo_cls: MagicMock,
    ) -> Iterator[None]:
        """Patch the top-level sigstore imports in the signature module."""
        with (
            patch("ggshield.core.plugin.signature.Bundle", mock_bundle_cls),
            patch("ggshield.core.plugin.signature.Verifier", mock_verifier_cls),
            patch("ggshield.core.plugin.signature.AllOf", mock_all_of_cls),
            patch(
                "ggshield.core.plugin.signature.OIDCIssuer",
                mock_oidc_issuer_cls,
            ),
            patch(
                "ggshield.core.plugin.signature.GitHubWorkflowRepository",
                mock_gh_repo_cls,
            ),
        ):
            yield

    def test_valid_signature(self, tmp_path: Path) -> None:
        """Test successful signature verification."""
        wheel = self._setup_wheel_and_bundle(tmp_path)

        mock_verifier_cls = MagicMock()
        mock_bundle_cls = MagicMock()
        mock_all_of_cls = MagicMock()
        mock_oidc_issuer_cls = MagicMock()
        mock_gh_repo_cls = MagicMock()

        mock_verifier = MagicMock()
        mock_verifier_cls.production.return_value = mock_verifier
        mock_verifier.verify_artifact.return_value = None  # Success

        mock_bundle = MagicMock()
        mock_bundle_cls.from_json.return_value = mock_bundle

        trusted = [
            TrustedIdentity(
                repository="GitGuardian/satori",
                issuer="https://token.actions.githubusercontent.com",
            )
        ]

        with self._sigstore_modules(
            mock_verifier_cls,
            mock_bundle_cls,
            mock_all_of_cls,
            mock_oidc_issuer_cls,
            mock_gh_repo_cls,
        ):
            result = verify_wheel_signature(
                wheel, SignatureVerificationMode.STRICT, trusted
            )

        assert result.status == SignatureStatus.VALID
        assert result.identity == trusted[0].repository

    def test_invalid_signature_strict_raises(self, tmp_path: Path) -> None:
        """Test that invalid signature raises in STRICT mode."""
        wheel = self._setup_wheel_and_bundle(tmp_path)

        mock_verifier_cls = MagicMock()
        mock_bundle_cls = MagicMock()
        mock_all_of_cls = MagicMock()
        mock_oidc_issuer_cls = MagicMock()
        mock_gh_repo_cls = MagicMock()

        mock_verifier = MagicMock()
        mock_verifier_cls.production.return_value = mock_verifier
        mock_verifier.verify_artifact.side_effect = Exception("Verification failed")

        mock_bundle = MagicMock()
        mock_bundle_cls.from_json.return_value = mock_bundle

        trusted = [
            TrustedIdentity(
                repository="GitGuardian/satori",
                issuer="https://token.actions.githubusercontent.com",
            )
        ]

        with self._sigstore_modules(
            mock_verifier_cls,
            mock_bundle_cls,
            mock_all_of_cls,
            mock_oidc_issuer_cls,
            mock_gh_repo_cls,
        ):
            with pytest.raises(SignatureVerificationError) as exc_info:
                verify_wheel_signature(wheel, SignatureVerificationMode.STRICT, trusted)

        assert exc_info.value.status == SignatureStatus.INVALID

    def test_invalid_signature_warn_returns_invalid(self, tmp_path: Path) -> None:
        """Test that invalid signature returns INVALID in WARN mode."""
        wheel = self._setup_wheel_and_bundle(tmp_path)

        mock_verifier_cls = MagicMock()
        mock_bundle_cls = MagicMock()
        mock_all_of_cls = MagicMock()
        mock_oidc_issuer_cls = MagicMock()
        mock_gh_repo_cls = MagicMock()

        mock_verifier = MagicMock()
        mock_verifier_cls.production.return_value = mock_verifier
        mock_verifier.verify_artifact.side_effect = Exception("Verification failed")

        mock_bundle = MagicMock()
        mock_bundle_cls.from_json.return_value = mock_bundle

        trusted = [
            TrustedIdentity(
                repository="org/repo",
                issuer="https://token.actions.githubusercontent.com",
            )
        ]

        with self._sigstore_modules(
            mock_verifier_cls,
            mock_bundle_cls,
            mock_all_of_cls,
            mock_oidc_issuer_cls,
            mock_gh_repo_cls,
        ):
            result = verify_wheel_signature(
                wheel, SignatureVerificationMode.WARN, trusted
            )

        assert result.status == SignatureStatus.INVALID

    def test_multi_identity_tries_all(self, tmp_path: Path) -> None:
        """Test that multiple trusted identities are tried in order."""
        wheel = self._setup_wheel_and_bundle(tmp_path)

        mock_verifier_cls = MagicMock()
        mock_bundle_cls = MagicMock()
        mock_all_of_cls = MagicMock()
        mock_oidc_issuer_cls = MagicMock()
        mock_gh_repo_cls = MagicMock()

        mock_verifier = MagicMock()
        mock_verifier_cls.production.return_value = mock_verifier
        # First identity fails, second succeeds
        mock_verifier.verify_artifact.side_effect = [
            Exception("Wrong identity"),
            None,  # Success
        ]

        mock_bundle = MagicMock()
        mock_bundle_cls.from_json.return_value = mock_bundle

        trusted = [
            TrustedIdentity(
                repository="other/repo",
                issuer="https://token.actions.githubusercontent.com",
            ),
            TrustedIdentity(
                repository="GitGuardian/satori",
                issuer="https://token.actions.githubusercontent.com",
            ),
        ]

        with self._sigstore_modules(
            mock_verifier_cls,
            mock_bundle_cls,
            mock_all_of_cls,
            mock_oidc_issuer_cls,
            mock_gh_repo_cls,
        ):
            result = verify_wheel_signature(
                wheel, SignatureVerificationMode.STRICT, trusted
            )

        assert result.status == SignatureStatus.VALID
        assert result.identity == trusted[1].repository
