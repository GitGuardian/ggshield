import hashlib
import logging
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml
from pygitguardian.models import RemediationMessages, SecretScanPreferences, TokenScope

from ggshield.core.dirs import get_cache_dir


logger = logging.getLogger(__name__)

# How long a successful auth check (metadata + token scopes) stays valid.
# Short enough that revoked tokens and scope changes propagate quickly;
# long enough that a burst of scans (e.g. IDE on-save) shares one check.
TTL_SECONDS = 300


def _cache_file() -> Path:
    # Resolved lazily so GG_CACHE_DIR overrides (tests, sandboxed envs) are honored.
    return get_cache_dir() / "auth_check.yaml"


@dataclass
class CachedAuthCheck:
    # If not None, these are the scopes fetched from /v1/api_tokens/self.
    # None means we haven't fetched scopes yet (e.g. from an auth-login flow
    # where no specific scopes were required).
    scopes: Optional[set[TokenScope]]
    secrets_engine_version: Optional[str]
    maximum_payload_size: Optional[int]
    secret_scan_preferences: Optional[SecretScanPreferences]
    remediation_messages: Optional[RemediationMessages]


def _key_hash(instance_url: str, api_key: str) -> str:
    return hashlib.sha256(f"{instance_url}\0{api_key}".encode("utf-8")).hexdigest()


def load(instance_url: str, api_key: str) -> Optional[CachedAuthCheck]:
    """Return the cached auth check for this (instance, key) pair, or None on miss."""
    path = _cache_file()
    try:
        with path.open("r") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        return None
    except (OSError, yaml.YAMLError) as e:
        logger.warning("Could not load auth check cache: %s", repr(e))
        return None

    if not isinstance(data, dict):
        return None
    if data.get("key_hash") != _key_hash(instance_url, api_key):
        return None
    if data.get("expires_at", 0) < time.time():
        return None

    raw_scopes = data.get("scopes")
    scopes: Optional[set[TokenScope]]
    if raw_scopes is None:
        scopes = None
    else:
        scopes = set()
        for scope_str in raw_scopes:
            try:
                scopes.add(TokenScope(scope_str))
            except ValueError:
                logger.debug("Ignoring unknown cached scope: '%s'", scope_str)

    raw_version = data.get("secrets_engine_version")
    secrets_engine_version = raw_version if isinstance(raw_version, str) else None

    raw_max_payload = data.get("maximum_payload_size")
    maximum_payload_size = raw_max_payload if isinstance(raw_max_payload, int) else None

    raw_ssp = data.get("secret_scan_preferences")
    secret_scan_preferences: Optional[SecretScanPreferences] = None
    if isinstance(raw_ssp, dict):
        try:
            secret_scan_preferences = SecretScanPreferences(**raw_ssp)
        except TypeError as e:
            logger.debug("Ignoring malformed cached secret_scan_preferences: %s", e)

    raw_rm = data.get("remediation_messages")
    remediation_messages: Optional[RemediationMessages] = None
    if isinstance(raw_rm, dict):
        try:
            remediation_messages = RemediationMessages(**raw_rm)
        except TypeError as e:
            logger.debug("Ignoring malformed cached remediation_messages: %s", e)

    return CachedAuthCheck(
        scopes=scopes,
        secrets_engine_version=secrets_engine_version,
        maximum_payload_size=maximum_payload_size,
        secret_scan_preferences=secret_scan_preferences,
        remediation_messages=remediation_messages,
    )


def store(instance_url: str, api_key: str, entry: CachedAuthCheck) -> None:
    """Record a successful auth check.

    Set entry.scopes=None if token scopes were not fetched (only metadata was checked).
    """
    ssp = entry.secret_scan_preferences
    rm = entry.remediation_messages
    payload = {
        "key_hash": _key_hash(instance_url, api_key),
        "scopes": (
            None if entry.scopes is None else sorted(s.value for s in entry.scopes)
        ),
        "secrets_engine_version": entry.secrets_engine_version,
        "maximum_payload_size": entry.maximum_payload_size,
        "secret_scan_preferences": (
            None
            if ssp is None
            else {
                "maximum_document_size": ssp.maximum_document_size,
                "maximum_documents_per_scan": ssp.maximum_documents_per_scan,
            }
        ),
        "remediation_messages": (
            None
            if rm is None
            else {
                "pre_commit": rm.pre_commit,
                "pre_push": rm.pre_push,
                "pre_receive": rm.pre_receive,
            }
        ),
        "expires_at": int(time.time()) + TTL_SECONDS,
    }

    path = _cache_file()
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Re-apply on a pre-existing dir, since mkdir's mode is ignored when the
        # dir already exists. Keeps the auth-check file out of reach of other
        # local users on shared POSIX hosts.
        try:
            os.chmod(path.parent, 0o700)
        except OSError as e:
            logger.debug("Could not tighten cache dir permissions: %s", repr(e))
        # Atomic write: a concurrent ggshield process would otherwise be able to
        # observe a truncated YAML file. tempfile in the same directory so
        # os.replace stays on one filesystem.
        fd, tmp_path = tempfile.mkstemp(
            prefix=".auth_check.", suffix=".tmp", dir=path.parent
        )
        try:
            os.chmod(tmp_path, 0o600)
            with os.fdopen(fd, "w") as f:
                yaml.dump(payload, f, indent=2, default_flow_style=False)
            os.replace(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except OSError as e:
        logger.warning("Could not save auth check cache: %s", repr(e))


def invalidate() -> None:
    """Drop the cached auth check, typically after a 401 from any API call."""
    try:
        _cache_file().unlink(missing_ok=True)
    except OSError as e:
        logger.warning("Could not invalidate auth check cache: %s", repr(e))
