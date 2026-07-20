"""Tests for plugin signature verification."""

import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from unittest.mock import MagicMock, patch

import pytest
from sigstore.errors import VerificationError as SigstoreVerificationError

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


class TestVerifierIsPinnedToBundledRoot:
    """Both modes must verify against the trust root bundled in the pinned
    sigstore release, never the cache/network-backed ``Verifier.production``
    path (which fails on locked-down networks: "failed to refresh TUF
    metadata")."""

    def _assert_uses_bundled_verifier(
        self, tmp_path: Path, mode: SignatureVerificationMode
    ) -> None:
        wheel = tmp_path / "plugin-1.0.0.whl"
        wheel.write_bytes(b"fake wheel content")
        bundle = tmp_path / "plugin-1.0.0.whl.sigstore"
        bundle.write_bytes(b'{"fake": "bundle"}')

        mock_verifier = MagicMock()
        mock_verifier.verify_artifact.return_value = None
        mock_verifier_cls = MagicMock()
        mock_bundle_cls = MagicMock()
        mock_bundle_cls.from_json.return_value = MagicMock()

        with (
            patch(
                "ggshield.core.plugin.signature._bundled_verifier",
                return_value=mock_verifier,
            ) as mock_bundled,
            patch("sigstore.verify.Verifier", mock_verifier_cls),
            patch("sigstore.models.Bundle", mock_bundle_cls),
            patch("sigstore.verify.policy.AllOf", MagicMock()),
            patch("sigstore.verify.policy.OIDCIssuer", MagicMock()),
            patch(
                "sigstore.verify.policy.GitHubWorkflowRepository",
                MagicMock(),
            ),
        ):
            verify_wheel_signature(wheel, mode)

        # The pinned, bundled verifier does the work...
        mock_bundled.assert_called_once_with()
        mock_verifier.verify_artifact.assert_called_once()
        # ...and the cache/network-backed production() path is never taken.
        mock_verifier_cls.production.assert_not_called()

    def test_strict_mode_uses_bundled_verifier(self, tmp_path: Path) -> None:
        self._assert_uses_bundled_verifier(tmp_path, SignatureVerificationMode.STRICT)

    def test_warn_mode_uses_bundled_verifier(self, tmp_path: Path) -> None:
        self._assert_uses_bundled_verifier(tmp_path, SignatureVerificationMode.WARN)


class TestBundleVerification:
    """Tests for bundle verification with a mocked (bundled) verifier."""

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
        mock_verifier: MagicMock,
        mock_bundle_cls: MagicMock,
        mock_all_of_cls: MagicMock,
        mock_oidc_issuer_cls: MagicMock,
        mock_gh_repo_cls: MagicMock,
    ) -> Iterator[None]:
        """Patch the sigstore seams: the bundled/pinned verifier plus the
        bundle and policy helpers used by the signature module."""
        with (
            patch("sigstore.models.Bundle", mock_bundle_cls),
            patch(
                "ggshield.core.plugin.signature._bundled_verifier",
                return_value=mock_verifier,
            ),
            patch("sigstore.verify.policy.AllOf", mock_all_of_cls),
            patch(
                "sigstore.verify.policy.OIDCIssuer",
                mock_oidc_issuer_cls,
            ),
            patch(
                "sigstore.verify.policy.GitHubWorkflowRepository",
                mock_gh_repo_cls,
            ),
        ):
            yield

    def test_valid_signature(self, tmp_path: Path) -> None:
        """Test successful signature verification."""
        wheel = self._setup_wheel_and_bundle(tmp_path)

        mock_verifier = MagicMock()
        mock_verifier.verify_artifact.return_value = None  # Success
        mock_bundle_cls = MagicMock()
        mock_bundle_cls.from_json.return_value = MagicMock()

        trusted = [
            TrustedIdentity(
                repository="GitGuardian/satori",
                issuer="https://token.actions.githubusercontent.com",
            )
        ]

        with self._sigstore_modules(
            mock_verifier,
            mock_bundle_cls,
            MagicMock(),
            MagicMock(),
            MagicMock(),
        ):
            result = verify_wheel_signature(
                wheel, SignatureVerificationMode.STRICT, trusted
            )

        assert result.status == SignatureStatus.VALID
        assert result.identity == trusted[0].repository

    def test_invalid_signature_strict_raises(self, tmp_path: Path) -> None:
        """Test that invalid signature raises in STRICT mode."""
        wheel = self._setup_wheel_and_bundle(tmp_path)

        mock_verifier = MagicMock()
        mock_verifier.verify_artifact.side_effect = SigstoreVerificationError(
            "Verification failed"
        )
        mock_bundle_cls = MagicMock()
        mock_bundle_cls.from_json.return_value = MagicMock()

        trusted = [
            TrustedIdentity(
                repository="GitGuardian/satori",
                issuer="https://token.actions.githubusercontent.com",
            )
        ]

        with self._sigstore_modules(
            mock_verifier,
            mock_bundle_cls,
            MagicMock(),
            MagicMock(),
            MagicMock(),
        ):
            with pytest.raises(SignatureVerificationError) as exc_info:
                verify_wheel_signature(wheel, SignatureVerificationMode.STRICT, trusted)

        assert exc_info.value.status == SignatureStatus.INVALID

    def test_invalid_signature_warn_returns_invalid(self, tmp_path: Path) -> None:
        """Test that invalid signature returns INVALID in WARN mode."""
        wheel = self._setup_wheel_and_bundle(tmp_path)

        mock_verifier = MagicMock()
        mock_verifier.verify_artifact.side_effect = SigstoreVerificationError(
            "Verification failed"
        )
        mock_bundle_cls = MagicMock()
        mock_bundle_cls.from_json.return_value = MagicMock()

        trusted = [
            TrustedIdentity(
                repository="org/repo",
                issuer="https://token.actions.githubusercontent.com",
            )
        ]

        with self._sigstore_modules(
            mock_verifier,
            mock_bundle_cls,
            MagicMock(),
            MagicMock(),
            MagicMock(),
        ):
            result = verify_wheel_signature(
                wheel, SignatureVerificationMode.WARN, trusted
            )

        assert result.status == SignatureStatus.INVALID

    def test_multi_identity_tries_all(self, tmp_path: Path) -> None:
        """Test that multiple trusted identities are tried in order."""
        wheel = self._setup_wheel_and_bundle(tmp_path)

        mock_verifier = MagicMock()
        # First identity fails, second succeeds
        mock_verifier.verify_artifact.side_effect = [
            SigstoreVerificationError("Wrong identity"),
            None,  # Success
        ]
        mock_bundle_cls = MagicMock()
        mock_bundle_cls.from_json.return_value = MagicMock()

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
            mock_verifier,
            mock_bundle_cls,
            MagicMock(),
            MagicMock(),
            MagicMock(),
        ):
            result = verify_wheel_signature(
                wheel, SignatureVerificationMode.STRICT, trusted
            )

        assert result.status == SignatureStatus.VALID
        assert result.identity == trusted[1].repository


class TestBundledVerifier:
    """Guards the private-sigstore wiring that pins the bundled trust root."""

    def test_resolves_embedded_root_and_skips_production(self) -> None:
        # Exercises the real embedded-root resolution (our vendored
        # TRUSTED_ROOT_JSON -> TrustedRoot.from_file). Verifier itself is mocked
        # so no real verifier/network is built; we only assert it is constructed
        # from a trusted_root, never via the cache/network-backed production().
        from ggshield.core.plugin.signature import _bundled_verifier

        _bundled_verifier.cache_clear()
        sentinel = MagicMock()
        try:
            with patch("sigstore.verify.Verifier") as mock_verifier_cls:
                mock_verifier_cls.return_value = sentinel
                result = _bundled_verifier()
        finally:
            _bundled_verifier.cache_clear()

        assert result is sentinel
        mock_verifier_cls.assert_called_once()
        assert "trusted_root" in mock_verifier_cls.call_args.kwargs
        mock_verifier_cls.production.assert_not_called()

    def test_builds_real_verifier_from_embedded_root(self) -> None:
        # End-to-end (no mocks): the vendored TRUSTED_ROOT_JSON must parse into a
        # real TrustedRoot and build a real, offline Verifier.
        from sigstore.verify import Verifier

        from ggshield.core.plugin.signature import _bundled_verifier

        _bundled_verifier.cache_clear()
        try:
            verifier = _bundled_verifier()
        finally:
            _bundled_verifier.cache_clear()

        assert isinstance(verifier, Verifier)

    @pytest.mark.skipif(
        sys.version_info < (3, 10),
        reason=(
            "Python < 3.10 resolves sigstore 4.1.x, which ships an older trusted "
            "root than the 4.2.x bundled in the released binaries (built on 3.10); "
            "we vendor the 4.2.x root."
        ),
    )
    def test_embedded_trusted_root_matches_sigstore(self) -> None:
        # The vendored copy must track the trusted_root.json shipped by the installed
        # sigstore; if a bump rotates the root this fails -> refresh
        # _sigstore_trusted_root.py.
        import json
        from importlib.resources import files
        from urllib.parse import quote

        from ggshield.core.plugin._sigstore_trusted_root import TRUSTED_ROOT_JSON
        from ggshield.core.plugin.signature import _SIGSTORE_PROD_TUF_URL

        sigstore_root = (
            files("sigstore._store")
            / quote(_SIGSTORE_PROD_TUF_URL, safe="")
            / "trusted_root.json"
        ).read_text()
        assert json.loads(TRUSTED_ROOT_JSON) == json.loads(sigstore_root)
