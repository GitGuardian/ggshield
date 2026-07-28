"""
Plugin signature verification using sigstore.

Provides keyless signature verification for plugin wheels using sigstore
bundles. Signatures are identity-based: ggshield trusts a configured set
of GitHub Actions workflow identities (OIDC).

Verification always runs against the trust root bundled inside our pinned
sigstore dependency (see ``_bundled_verifier``). ggshield never refreshes TUF
metadata over the network, because that refresh fails on locked-down / proxied
networks ("failed to refresh TUF metadata"). The bundled root is enough to
verify GitGuardian's own plugin signatures; the trade-off is that trust-root
freshness tracks the pinned sigstore version, so keep that dependency current.

Verification modes (these decide how a result is handled, not how it is computed):
- STRICT: block unsigned or invalid plugins
- WARN: log a warning but allow loading (the ``--allow-unsigned`` override)
- DISABLED: skip verification entirely
"""

from __future__ import annotations

import enum
import functools
import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional

from ggshield.core.plugin._sigstore_trusted_root import TRUSTED_ROOT_JSON


if TYPE_CHECKING:
    # Imported lazily at call time (see _bundled_verifier / verify_wheel_signature)
    # so that merely importing this module -- e.g. for SignatureVerificationMode,
    # used when constructing PluginLoader on every ggshield invocation -- does not
    # drag in the whole sigstore/pydantic/rekor stack (~500ms of imports).
    from sigstore.verify import Verifier


logger = logging.getLogger(__name__)


class SignatureVerificationMode(enum.Enum):
    """How strictly to enforce plugin signatures."""

    STRICT = "strict"
    WARN = "warn"
    DISABLED = "disabled"


class SignatureStatus(enum.Enum):
    """Result of signature verification."""

    VALID = "valid"
    MISSING = "missing"
    INVALID = "invalid"
    SKIPPED = "skipped"


@dataclass
class TrustedIdentity:
    """An OIDC identity trusted to sign plugins."""

    repository: str
    """GitHub repository (e.g. "GitGuardian/satori")."""

    issuer: str
    """OIDC issuer URL."""


@dataclass
class SignatureInfo:
    """Result of verifying a wheel's signature."""

    status: SignatureStatus
    identity: Optional[str] = None
    message: Optional[str] = None


class SignatureVerificationError(Exception):
    """Raised when signature verification fails in strict mode."""

    def __init__(self, status: SignatureStatus, message: str) -> None:
        self.status = status
        super().__init__(message)


# Default trusted identities: GitHub Actions workflows that are authorized
# to sign plugin wheels.
DEFAULT_TRUSTED_IDENTITIES: List[TrustedIdentity] = [
    TrustedIdentity(
        repository="GitGuardian/satori",
        issuer="https://token.actions.githubusercontent.com",
    ),
]


def get_bundle_path(wheel_path: Path) -> Optional[Path]:
    """Return the sigstore bundle path for a wheel, or None if not found.

    Checks for `.sigstore` first, then `.sigstore.json` (sigstore-python 3.x
    default) so that both old and new naming conventions are supported.
    """
    for ext in (".sigstore", ".sigstore.json"):
        p = wheel_path.parent / (wheel_path.name + ext)
        if p.exists():
            return p
    return None


# Only used by the freshness test, to find sigstore's own trusted_root.json
# (under its URL-encoded _store dir) and compare it to our vendored copy.
_SIGSTORE_PROD_TUF_URL = "https://tuf-repo-cdn.sigstore.dev"


@functools.lru_cache(maxsize=1)
def _bundled_verifier() -> Verifier:
    """Build a Verifier pinned to a vendored copy of sigstore's production trust root.

    We verify against ``_sigstore_trusted_root.TRUSTED_ROOT_JSON`` -- a copy of
    sigstore's production ``trusted_root.json`` committed in ggshield -- instead
    of sigstore's own ``_store`` resource. sigstore 4.x ships that file under a
    URL-encoded directory (``https%3A%2F%2Ftuf-repo-cdn.sigstore.dev``) whose
    ``%`` path characters break Chocolatey's server-side .nupkg extraction;
    reading our own copy keeps those names out of the bundle. It is
    also deterministic and never touches the network -- the TUF refresh behind
    ``Verifier.production`` is what fails on locked-down / proxied networks with
    "failed to refresh TUF metadata".

    ``TrustedRoot.from_file`` is sigstore's only public constructor, so the
    embedded JSON is materialised to a temp file to load it.
    """
    from sigstore.models import TrustedRoot
    from sigstore.verify import Verifier

    with tempfile.TemporaryDirectory() as tmp_dir:
        trusted_root_path = Path(tmp_dir) / "trusted_root.json"
        trusted_root_path.write_text(TRUSTED_ROOT_JSON)
        trusted_root = TrustedRoot.from_file(str(trusted_root_path))
    return Verifier(trusted_root=trusted_root)


def verify_wheel_signature(
    wheel_path: Path,
    mode: SignatureVerificationMode,
    trusted_identities: Optional[List[TrustedIdentity]] = None,
) -> SignatureInfo:
    """
    Verify the sigstore signature of a plugin wheel.

    Args:
        wheel_path: Path to the .whl file.
        mode: Verification strictness.
        trusted_identities: OIDC identities to trust.
            Defaults to DEFAULT_TRUSTED_IDENTITIES.

    Returns:
        SignatureInfo with the verification result.

    Raises:
        SignatureVerificationError: In STRICT mode when the signature is
            missing or invalid.
    """
    if mode == SignatureVerificationMode.DISABLED:
        return SignatureInfo(status=SignatureStatus.SKIPPED)

    if trusted_identities is None:
        trusted_identities = DEFAULT_TRUSTED_IDENTITIES

    bundle_path = get_bundle_path(wheel_path)

    # Missing bundle
    if bundle_path is None:
        msg = f"No signature bundle found for {wheel_path.name}"
        if mode == SignatureVerificationMode.STRICT:
            raise SignatureVerificationError(SignatureStatus.MISSING, msg)
        logger.warning("%s", msg)
        return SignatureInfo(status=SignatureStatus.MISSING, message=msg)

    from sigstore.errors import VerificationError
    from sigstore.models import Bundle
    from sigstore.verify.policy import AllOf, GitHubWorkflowRepository, OIDCIssuer

    bundle = Bundle.from_json(bundle_path.read_bytes())
    wheel_bytes = wheel_path.read_bytes()
    verifier = _bundled_verifier()

    for trusted in trusted_identities:
        policy = AllOf(
            [
                OIDCIssuer(trusted.issuer),
                GitHubWorkflowRepository(trusted.repository),
            ]
        )
        try:
            verifier.verify_artifact(
                input_=wheel_bytes,
                bundle=bundle,
                policy=policy,
            )
            logger.info(
                "Signature valid for %s (repository: %s)",
                wheel_path.name,
                trusted.repository,
            )
            return SignatureInfo(
                status=SignatureStatus.VALID,
                identity=trusted.repository,
            )
        except VerificationError as e:
            logger.debug(
                "Identity %s did not match for %s: %s",
                trusted.repository,
                wheel_path.name,
                e,
            )
            continue

    # No identity matched
    msg = f"Signature verification failed for {wheel_path.name}: no trusted identity matched"
    if mode == SignatureVerificationMode.STRICT:
        raise SignatureVerificationError(SignatureStatus.INVALID, msg)
    logger.warning("%s", msg)
    return SignatureInfo(status=SignatureStatus.INVALID, message=msg)
