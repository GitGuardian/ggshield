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
import json
import logging
import os
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from ggshield.core.dirs import is_safe_system_path
from ggshield.core.plugin._sigstore_trusted_root import TRUSTED_ROOT_JSON


if TYPE_CHECKING:
    # Imported lazily at call time (see _bundled_verifier / verify_wheel_signature)
    # so that merely importing this module -- e.g. for SignatureVerificationMode,
    # used when constructing PluginLoader on every ggshield invocation -- does not
    # drag in the whole sigstore/pydantic/rekor stack (~500ms of imports).
    from sigstore.verify import Verifier


logger = logging.getLogger(__name__)

_BUNDLE_EXTENSIONS = (".sigstore", ".sigstore.json")


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
    for ext in _BUNDLE_EXTENSIONS:
        p = wheel_path.parent / (wheel_path.name + ext)
        if p.exists():
            return p
    return None


def read_plugin_wheel(
    plugin_dir: Path,
    *,
    secondary: bool,
    allow_missing_wheel: bool = False,
    warn_invalid_manifest: bool = False,
    skip_reasons: Optional[List[str]] = None,
) -> Optional[Tuple[Dict[str, Any], Optional[Path]]]:
    """Read an eligible plugin manifest and its wheel path.

    When the plugin is skipped, the reason is appended to ``skip_reasons``
    (for ``plugin list -v``)."""

    def skip(reason: str) -> None:
        if skip_reasons is not None:
            skip_reasons.append(reason)

    unsafe = "not owned by root, or writable by others (XDG_DATA_DIRS entry)"
    manifest_path = plugin_dir / "manifest.json"
    if secondary and not is_safe_system_path(plugin_dir, directory=True):
        skip(f"folder {unsafe}")
        return None
    try:
        if not plugin_dir.is_dir():
            return None
        try:
            manifest_path.lstat()
        except FileNotFoundError:
            skip("no manifest.json")
            return None
        if secondary and not is_safe_system_path(manifest_path):
            skip(f"manifest.json {unsafe}")
            return None
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        # An empty manifest can still identify a stale fixed or user install.
        if allow_missing_wheel and manifest == {}:
            return manifest, None
        if not isinstance(manifest, dict):
            raise ValueError("expected a JSON object")
        for key in ("wheel_filename", "plugin_name", "version"):
            value = manifest.get(key)
            if not isinstance(value, str) or not value:
                raise ValueError(f"expected a non-empty {key}")
        filename = manifest["wheel_filename"]
        if filename in (".", "..") or any(
            char in filename for char in ("/", "\\", ":", "\x00")
        ):
            raise ValueError(f"invalid wheel filename {filename!r}")
    except ValueError as e:
        level = logging.WARNING if warn_invalid_manifest else logging.DEBUG
        logger.log(level, "Invalid manifest in %s: %s", plugin_dir, e)
        skip(f"invalid manifest: {e}")
        return None
    except OSError as e:
        logger.debug("Cannot read manifest in %s: %s", plugin_dir, e)
        skip(f"invalid manifest: {e}")
        return None

    wheel_path = plugin_dir / filename
    try:
        if not stat.S_ISREG(wheel_path.stat().st_mode) or not os.access(
            wheel_path, os.R_OK
        ):
            logger.debug("Ignoring unreadable plugin wheel %s", wheel_path)
            skip(f"wheel {filename} unreadable")
            return None
    except FileNotFoundError:
        if allow_missing_wheel:
            return manifest, None
        skip(f"wheel {filename} missing")
        return None
    except (OSError, ValueError) as e:
        logger.debug("Cannot read plugin wheel %s: %s", wheel_path, e)
        skip(f"cannot read wheel {filename}: {e}")
        return None

    if secondary:
        if not is_safe_system_path(wheel_path) or not all(
            is_safe_system_path(
                wheel_path.with_name(filename + ext), allow_missing=True
            )
            for ext in _BUNDLE_EXTENSIONS
        ):
            skip(f"wheel or signature {unsafe}")
            return None
        # A corrupt copy must not shadow a working one in a later XDG entry.
        if not zipfile.is_zipfile(wheel_path):
            skip(f"wheel {filename} is not a valid archive")
            return None
    return manifest, wheel_path


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
