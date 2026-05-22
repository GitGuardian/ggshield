import os
import stat
import time
from unittest.mock import Mock

import click
import pytest
from pygitguardian import GGClient
from pygitguardian.models import (
    APITokensResponse,
    Detail,
    RemediationMessages,
    SecretScanPreferences,
    TokenScope,
)

from ggshield.core import auth_check_cache
from ggshield.core.client import check_client_api_key
from ggshield.core.errors import APIKeyCheckError, handle_api_error
from tests.conftest import skipwindows


API_TOKENS_RESPONSE = APITokensResponse.from_dict(
    {
        "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
        "name": "test-name",
        "workspace_id": 1,
        "type": "personal_access_token",
        "status": "active",
        "created_at": "2023-01-01T00:00:00Z",
        "scopes": [TokenScope.SCAN_CREATE_INCIDENTS.value],
    }
)


def _entry(
    scopes=None,
    secrets_engine_version=None,
    maximum_payload_size=None,
    secret_scan_preferences=None,
    remediation_messages=None,
) -> auth_check_cache.CachedAuthCheck:
    return auth_check_cache.CachedAuthCheck(
        scopes=scopes,
        secrets_engine_version=secrets_engine_version,
        maximum_payload_size=maximum_payload_size,
        secret_scan_preferences=secret_scan_preferences,
        remediation_messages=remediation_messages,
    )


def _make_client_mock() -> Mock:
    client_mock = Mock(spec=GGClient)
    client_mock.base_uri = "http://localhost"
    client_mock.api_key = "test-api-key"
    client_mock.secrets_engine_version = "2.0.0"
    client_mock.maximum_payload_size = 1_000_000
    client_mock.secret_scan_preferences = SecretScanPreferences(
        maximum_document_size=2_000_000, maximum_documents_per_scan=42
    )
    client_mock.remediation_messages = RemediationMessages(
        pre_commit="custom pre-commit",
        pre_push="custom pre-push",
        pre_receive="custom pre-receive",
    )
    client_mock.read_metadata.return_value = None  # Success
    client_mock.api_tokens.return_value = API_TOKENS_RESPONSE
    return client_mock


def test_cache_skips_metadata_and_api_tokens_on_hit():
    """
    GIVEN a prior successful check populated the cache
    WHEN check_client_api_key is called again with the same scopes
    THEN neither read_metadata nor api_tokens is called
    """
    client_mock = _make_client_mock()

    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})
    client_mock.read_metadata.reset_mock()
    client_mock.api_tokens.reset_mock()

    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})

    client_mock.read_metadata.assert_not_called()
    client_mock.api_tokens.assert_not_called()


def test_cache_hit_restores_metadata_side_effects_on_client():
    """
    GIVEN a prior check populated the cache while /v1/metadata set
          secrets_engine_version, maximum_payload_size, secret_scan_preferences
          and remediation_messages on the client
    WHEN a subsequent check hits the cache and skips /v1/metadata
    THEN every metadata side effect is restored onto the fresh client.

    Without this, a warm-cache fresh process silently falls back to
    pygitguardian defaults — wrong scan chunk size and generic remediation
    messages for instances that customize them.
    """
    client_mock = _make_client_mock()
    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})

    # Simulate a fresh subprocess: a new client with defaults reset.
    fresh_client = _make_client_mock()
    fresh_client.secrets_engine_version = None
    fresh_client.maximum_payload_size = -1
    fresh_client.secret_scan_preferences = SecretScanPreferences()
    fresh_client.remediation_messages = RemediationMessages()

    check_client_api_key(fresh_client, {TokenScope.SCAN_CREATE_INCIDENTS})

    fresh_client.read_metadata.assert_not_called()
    fresh_client.api_tokens.assert_not_called()
    assert fresh_client.secrets_engine_version == "2.0.0"
    assert fresh_client.maximum_payload_size == 1_000_000
    assert fresh_client.secret_scan_preferences == SecretScanPreferences(
        maximum_document_size=2_000_000, maximum_documents_per_scan=42
    )
    assert fresh_client.remediation_messages == RemediationMessages(
        pre_commit="custom pre-commit",
        pre_push="custom pre-push",
        pre_receive="custom pre-receive",
    )


def test_cache_miss_on_different_api_key():
    """
    GIVEN the cache was populated for one api_key
    WHEN the same instance is checked with a different api_key
    THEN the cache does not short-circuit
    """
    client_mock = _make_client_mock()
    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})

    client_mock.api_key = "different-api-key"
    client_mock.read_metadata.reset_mock()
    client_mock.api_tokens.reset_mock()

    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})

    client_mock.read_metadata.assert_called_once()
    client_mock.api_tokens.assert_called_once()


def test_cache_hit_for_metadata_still_fetches_scopes_when_needed():
    """
    GIVEN a cache entry seeded without scopes (e.g. from an auth-login flow)
    WHEN check_client_api_key runs with required scopes
    THEN read_metadata is skipped but api_tokens is still fetched
    """
    client_mock = _make_client_mock()
    check_client_api_key(client_mock, set())  # caches with scopes=None
    client_mock.read_metadata.reset_mock()
    client_mock.api_tokens.reset_mock()

    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})

    client_mock.read_metadata.assert_not_called()
    client_mock.api_tokens.assert_called_once()


def test_cache_hit_with_narrower_scopes_refetches_and_widens_cache():
    """
    GIVEN a cache entry whose scopes are a strict subset of what the next
          call requires (cached={SCAN_CREATE_INCIDENTS}, required adds SCAN)
    WHEN check_client_api_key runs
    THEN read_metadata is skipped (cache hit on metadata) but api_tokens is
         re-fetched, and the cache is rewritten with the wider scope set so
         the next call with the same required_scopes early-returns.
    """
    client_mock = _make_client_mock()
    # Seed cache directly with the narrower scope set (simulates a prior call
    # whose required_scopes happened to be just SCAN_CREATE_INCIDENTS).
    auth_check_cache.store(
        client_mock.base_uri,
        client_mock.api_key,
        _entry(scopes={TokenScope.SCAN_CREATE_INCIDENTS}),
    )
    client_mock.api_tokens.return_value = APITokensResponse.from_dict(
        {
            "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
            "name": "test-name",
            "workspace_id": 1,
            "type": "personal_access_token",
            "status": "active",
            "created_at": "2023-01-01T00:00:00Z",
            "scopes": [TokenScope.SCAN_CREATE_INCIDENTS.value, TokenScope.SCAN.value],
        }
    )

    # Require a superset — should skip read_metadata but re-fetch api_tokens.
    check_client_api_key(
        client_mock, {TokenScope.SCAN_CREATE_INCIDENTS, TokenScope.SCAN}
    )
    client_mock.read_metadata.assert_not_called()
    client_mock.api_tokens.assert_called_once()

    # Cache should now hold the wider set — a repeat call must early-return.
    client_mock.api_tokens.reset_mock()
    check_client_api_key(
        client_mock, {TokenScope.SCAN_CREATE_INCIDENTS, TokenScope.SCAN}
    )
    client_mock.read_metadata.assert_not_called()
    client_mock.api_tokens.assert_not_called()


def test_api_tokens_401_invalidates_cache_and_raises_auth_error():
    """
    GIVEN a no-scope cache entry whose token has since been revoked
    WHEN a scope-requiring check falls through to api_tokens() and gets 401
    THEN the cache is invalidated and APIKeyCheckError is raised so the
         caller learns the key is invalid (not just an UnexpectedError that
         leaves the stale entry behind to mask the next call too).
    """
    client_mock = _make_client_mock()
    check_client_api_key(client_mock, set())  # seed no-scope entry
    assert auth_check_cache.load("http://localhost", "test-api-key") is not None

    client_mock.read_metadata.reset_mock()
    client_mock.api_tokens.return_value = Detail("Invalid API key", 401)

    with pytest.raises(APIKeyCheckError):
        check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})

    client_mock.read_metadata.assert_not_called()
    assert auth_check_cache.load("http://localhost", "test-api-key") is None


def test_expired_cache_is_ignored(monkeypatch):
    """
    GIVEN the cache TTL has elapsed
    WHEN check_client_api_key runs
    THEN both calls are made again
    """
    client_mock = _make_client_mock()
    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})

    later = time.time() + auth_check_cache.TTL_SECONDS + 1
    monkeypatch.setattr(auth_check_cache.time, "time", lambda: later)
    client_mock.read_metadata.reset_mock()
    client_mock.api_tokens.reset_mock()

    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})

    client_mock.read_metadata.assert_called_once()
    client_mock.api_tokens.assert_called_once()


def test_invalidate_removes_cache_entry():
    client_mock = _make_client_mock()
    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})
    assert auth_check_cache.load("http://localhost", "test-api-key") is not None

    auth_check_cache.invalidate()

    assert auth_check_cache.load("http://localhost", "test-api-key") is None


def test_handle_api_error_401_invalidates_cache():
    """
    GIVEN the cache was populated by a successful auth check
    WHEN any later API call surfaces a 401 through handle_api_error
    THEN the cache entry is dropped so the next check re-verifies the key
    """
    client_mock = _make_client_mock()
    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})
    assert auth_check_cache.load("http://localhost", "test-api-key") is not None

    with pytest.raises(click.UsageError):
        handle_api_error(Detail("Invalid API key", 401))

    assert auth_check_cache.load("http://localhost", "test-api-key") is None


def test_load_returns_none_on_corrupt_yaml():
    """
    GIVEN the cache file contains bytes that are not valid YAML
    WHEN load is called
    THEN it returns None instead of propagating the parse error
    """
    cache_file = auth_check_cache._cache_file()
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text("not: valid: yaml: [")

    assert auth_check_cache.load("http://localhost", "test-api-key") is None


def test_load_ignores_unknown_cached_scope():
    """
    GIVEN a cache entry persisted an API scope the current ggshield build does
          not know about (forward compatibility with a newer API)
    WHEN load decodes it
    THEN the unknown scope is dropped and the rest of the entry is returned
    """
    auth_check_cache.store(
        "http://localhost",
        "test-api-key",
        _entry(
            scopes={TokenScope.SCAN_CREATE_INCIDENTS},
            secrets_engine_version="2.0.0",
            maximum_payload_size=1_000_000,
            secret_scan_preferences=SecretScanPreferences(),
            remediation_messages=RemediationMessages(),
        ),
    )
    # Inject an extra scope the enum does not know about by rewriting the file.
    import yaml

    path = auth_check_cache._cache_file()
    with path.open("r") as f:
        data = yaml.safe_load(f)
    assert data is not None
    data["scopes"] = sorted(data["scopes"] + ["scan:future_scope_not_in_enum"])
    with path.open("w") as f:
        yaml.dump(data, f)

    cached = auth_check_cache.load("http://localhost", "test-api-key")

    assert cached is not None
    assert cached.scopes == {TokenScope.SCAN_CREATE_INCIDENTS}


def test_store_failure_is_swallowed(monkeypatch, caplog):
    """
    GIVEN saving the cache file raises (e.g. disk full, read-only FS)
    WHEN store is called
    THEN the error is logged and does not propagate to the caller
    """

    def _boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(auth_check_cache.tempfile, "mkstemp", _boom)

    auth_check_cache.store("http://localhost", "test-api-key", _entry())

    assert any("Could not save auth check cache" in r.message for r in caplog.records)


def test_invalidate_failure_is_swallowed(monkeypatch, caplog):
    """
    GIVEN unlinking the cache file raises (e.g. permission error)
    WHEN invalidate is called
    THEN the error is logged and does not propagate
    """

    def _boom(*args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(auth_check_cache.Path, "unlink", _boom)

    auth_check_cache.invalidate()

    assert any(
        "Could not invalidate auth check cache" in r.message for r in caplog.records
    )


@skipwindows
def test_store_creates_cache_dir_with_0700():
    """
    GIVEN no cache directory yet
    WHEN store creates it
    THEN the directory is 0700 so other local users cannot list or open the
         auth-check file inside it
    """
    cache_dir = auth_check_cache._cache_file().parent
    assert not cache_dir.exists()

    auth_check_cache.store("http://localhost", "test-api-key", _entry())

    assert stat.S_IMODE(cache_dir.stat().st_mode) == 0o700


def test_load_returns_none_when_yaml_is_not_a_dict():
    """
    GIVEN the cache file parses to a non-mapping (e.g. a stray list or scalar
          left over from a hand-edit or an older incompatible format)
    WHEN load is called
    THEN it returns None rather than blowing up on a missing .get
    """
    cache_file = auth_check_cache._cache_file()
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text("- just\n- a\n- list\n")

    assert auth_check_cache.load("http://localhost", "test-api-key") is None


def test_load_ignores_malformed_cached_secret_scan_preferences():
    """
    GIVEN a cache entry whose persisted secret_scan_preferences dict cannot be
          mapped onto SecretScanPreferences (unexpected keys)
    WHEN load decodes it
    THEN secret_scan_preferences comes back as None and the rest of the entry
         is still returned
    """
    auth_check_cache.store(
        "http://localhost",
        "test-api-key",
        _entry(
            scopes={TokenScope.SCAN_CREATE_INCIDENTS},
            secrets_engine_version="2.0.0",
            maximum_payload_size=1_000_000,
            secret_scan_preferences=SecretScanPreferences(),
            remediation_messages=RemediationMessages(),
        ),
    )
    import yaml

    path = auth_check_cache._cache_file()
    with path.open("r") as f:
        data = yaml.safe_load(f)
    data["secret_scan_preferences"] = {"not_a_real_field": 1}
    with path.open("w") as f:
        yaml.dump(data, f)

    cached = auth_check_cache.load("http://localhost", "test-api-key")

    assert cached is not None
    assert cached.secret_scan_preferences is None
    assert cached.scopes == {TokenScope.SCAN_CREATE_INCIDENTS}


def test_load_ignores_malformed_cached_remediation_messages():
    """
    GIVEN a cache entry whose persisted remediation_messages dict cannot be
          mapped onto RemediationMessages (unexpected keys)
    WHEN load decodes it
    THEN remediation_messages comes back as None and the rest of the entry
         is still returned
    """
    auth_check_cache.store(
        "http://localhost",
        "test-api-key",
        _entry(
            scopes={TokenScope.SCAN_CREATE_INCIDENTS},
            secrets_engine_version="2.0.0",
            maximum_payload_size=1_000_000,
            secret_scan_preferences=SecretScanPreferences(),
            remediation_messages=RemediationMessages(),
        ),
    )
    import yaml

    path = auth_check_cache._cache_file()
    with path.open("r") as f:
        data = yaml.safe_load(f)
    data["remediation_messages"] = {"not_a_real_field": "x"}
    with path.open("w") as f:
        yaml.dump(data, f)

    cached = auth_check_cache.load("http://localhost", "test-api-key")

    assert cached is not None
    assert cached.remediation_messages is None
    assert cached.scopes == {TokenScope.SCAN_CREATE_INCIDENTS}


@skipwindows
def test_store_tolerates_chmod_failure_on_existing_dir(monkeypatch, caplog):
    """
    GIVEN the cache directory already exists and os.chmod fails on it (e.g.
          the dir is owned by another user on a shared host)
    WHEN store runs
    THEN the failure is logged at debug level and the cache file is still
         written
    """
    cache_dir = auth_check_cache._cache_file().parent
    cache_dir.mkdir(parents=True, exist_ok=True)

    real_chmod = os.chmod

    def _chmod(path, mode, *args, **kwargs):
        if str(path) == str(cache_dir):
            raise OSError("permission denied")
        return real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(auth_check_cache.os, "chmod", _chmod)

    auth_check_cache.store("http://localhost", "test-api-key", _entry())

    assert auth_check_cache.load("http://localhost", "test-api-key") is not None


def test_store_swallows_failure_when_tempfile_cleanup_also_fails(monkeypatch):
    """
    GIVEN yaml.dump raises mid-write AND the tempfile cleanup itself raises
          (a doubly-degraded filesystem state)
    WHEN store runs
    THEN the outer error handler still swallows the failure rather than
         letting the secondary unlink error escape the cache layer
    """
    cache_dir = auth_check_cache._cache_file().parent
    cache_dir.mkdir(parents=True, exist_ok=True)

    def _boom_dump(*args, **kwargs):
        raise OSError("disk full")

    def _boom_unlink(*args, **kwargs):
        raise OSError("unlink failed")

    monkeypatch.setattr(auth_check_cache.yaml, "dump", _boom_dump)
    monkeypatch.setattr(auth_check_cache.os, "unlink", _boom_unlink)

    auth_check_cache.store("http://localhost", "test-api-key", _entry())

    assert not auth_check_cache._cache_file().exists()


def test_store_cleans_up_tempfile_when_write_fails(monkeypatch):
    """
    GIVEN yaml.dump raises mid-write (e.g. disk fills up between mkstemp and
          replace)
    WHEN store handles the failure
    THEN the temporary file is unlinked so we do not leak .auth_check.*.tmp
         files into the cache dir on repeated failures
    """
    cache_dir = auth_check_cache._cache_file().parent
    cache_dir.mkdir(parents=True, exist_ok=True)

    def _boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(auth_check_cache.yaml, "dump", _boom)

    auth_check_cache.store("http://localhost", "test-api-key", _entry())

    leftovers = list(cache_dir.glob(".auth_check.*.tmp"))
    assert leftovers == []
    assert not auth_check_cache._cache_file().exists()


@skipwindows
def test_store_tightens_existing_cache_dir_permissions():
    """
    GIVEN a cache directory pre-created with permissive (0755) permissions
    WHEN store writes the auth-check file
    THEN the directory is re-chmod'd to 0700
    """
    cache_dir = auth_check_cache._cache_file().parent
    cache_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(cache_dir, 0o755)

    auth_check_cache.store("http://localhost", "test-api-key", _entry())

    assert stat.S_IMODE(cache_dir.stat().st_mode) == 0o700
