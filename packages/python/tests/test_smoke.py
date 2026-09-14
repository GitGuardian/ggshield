"""Offline smoke tests for the gitguardian SDK.

These run without a secret-manager server: the env-override path never
touches the network, and the provider-read tests point VAULT_ADDR at a
closed local port so failures are immediate.
"""

import pytest

from gitguardian import Provider, Secret, SecretError, SecretStore

UNREACHABLE_VAULT = "http://127.0.0.1:9"


def test_env_override_short_circuits_the_provider(monkeypatch):
    # No VAULT_ADDR configured: the lookup must return before any provider
    # access happens.
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.setenv("SMOKE_TEST_FIELD", "value-from-env")

    store = SecretStore(Provider.VAULT)
    secret = store.get_secret("secret/does-not-matter", "SMOKE_TEST_FIELD")

    assert isinstance(secret, Secret)
    assert secret.expose() == "value-from-env"


def test_secret_is_redacted_by_default(monkeypatch):
    monkeypatch.setenv("SMOKE_TEST_FIELD", "value-from-env")
    secret = SecretStore(Provider.VAULT).get_secret("secret/x", "SMOKE_TEST_FIELD")

    assert "value-from-env" not in repr(secret)
    assert "value-from-env" not in str(secret)


def test_env_override_can_be_disabled(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", UNREACHABLE_VAULT)
    monkeypatch.setenv("VAULT_TOKEN", "fake-token")
    monkeypatch.setenv("SMOKE_TEST_FIELD", "value-from-env")

    store = SecretStore(Provider.VAULT, env_override=False)
    with pytest.raises(SecretError):
        store.get_secret("secret/myapp", "SMOKE_TEST_FIELD")


def test_provider_failure_raises_secret_error(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", UNREACHABLE_VAULT)
    monkeypatch.setenv("VAULT_TOKEN", "fake-token")

    store = SecretStore(Provider.VAULT)
    with pytest.raises(SecretError) as excinfo:
        store.get_secrets("secret/myapp")
    assert "read_secret" in str(excinfo.value)


def test_non_http_base_urls_are_rejected(monkeypatch):
    # urllib would happily open file:// URLs; a poisoned VAULT_ADDR must not
    # be able to turn a secret read into a local file read.
    monkeypatch.setenv("VAULT_ADDR", "file:///etc/passwd")
    monkeypatch.setenv("VAULT_TOKEN", "fake-token")

    store = SecretStore(Provider.VAULT, env_override=False)
    with pytest.raises(SecretError, match="must be http"):
        store.get_secrets("secret/myapp")


def test_set_secrets_rejects_empty_fields():
    # Guarded before any provider access, so no server is needed.
    with pytest.raises(SecretError, match="cannot set a secret with no fields"):
        SecretStore(Provider.VAULT).set_secrets("secret/myapp", {})


def test_writes_reach_the_provider_and_surface_failures(monkeypatch):
    # The write path is otherwise exercised end-to-end against a throwaway
    # vault dev-server (see AGENTS.md); here we only assert it reaches the
    # provider and maps transport failures to SecretError.
    monkeypatch.setenv("VAULT_ADDR", UNREACHABLE_VAULT)
    monkeypatch.setenv("VAULT_TOKEN", "fake-token")
    store = SecretStore(Provider.VAULT)

    with pytest.raises(SecretError):
        store.set_secrets("secret/myapp", {"API_KEY": "fake"})
    with pytest.raises(SecretError):
        store.delete_secrets("secret/myapp")
