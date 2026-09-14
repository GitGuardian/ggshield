"""Unit tests for the engine internals, mirroring packages/core's Rust tests."""

import pytest

from gitguardian import Provider, SecretError, SecretStore
from gitguardian._auth import auth_headers, resolve_token, token_file_path
from gitguardian._definition import TokenAuth
from gitguardian._json import dot_path, secret_fields
from gitguardian._onepassword import (
    merge_item_fields,
    parse_path,
    remove_item_fields,
    resolve_id,
)
from gitguardian._store import (
    _interpolate,
    _interpolate_path,
    _read_params,
    _truncate,
)


def test_interpolate_resolves_params_then_env(monkeypatch):
    monkeypatch.setenv("GG_TEST_INTERP", "from-env")
    assert (
        _interpolate("${mount}/${GG_TEST_INTERP}", {"mount": "from-params"})
        == "from-params/from-env"
    )
    with pytest.raises(SecretError, match="no value for"):
        _interpolate("${GG_TEST_UNSET_INTERP}", {})
    with pytest.raises(SecretError, match="unterminated"):
        _interpolate("${oops", {})


def test_interpolate_path_percent_encodes_values_but_keeps_slashes():
    encoded = _interpolate_path("/v1/${path}", {"path": "a/b#c?d %e"})
    assert encoded == "/v1/a/b%23c%3Fd%20%25e"
    # Template literals are trusted and left as-is.
    assert _interpolate_path("/v1/data?x=1", {}) == "/v1/data?x=1"
    assert _interpolate_path("/v1/${item_id}", {"item_id": "item/id"}) == (
        "/v1/item%2Fid"
    )


def test_read_params_splits_mount_and_path():
    assert _read_params("secret/myapp/db") == {"mount": "secret", "path": "myapp/db"}
    with pytest.raises(SecretError, match="must be '<mount>/<path>'"):
        _read_params("no-slash")


def test_resolve_token_prefers_env_then_file(tmp_path, monkeypatch):
    token_file = tmp_path / "token"
    token_file.write_text("  s.abc123\n")
    auth = TokenAuth(token_env="GG_TEST_TOKEN", token_file=str(token_file))

    monkeypatch.setenv("GG_TEST_TOKEN", "from-env")
    assert resolve_token(auth) == "from-env"

    monkeypatch.delenv("GG_TEST_TOKEN")
    assert resolve_token(auth) == "s.abc123"


def test_resolve_token_treats_a_missing_file_as_no_token(monkeypatch):
    monkeypatch.delenv("GG_TEST_TOKEN", raising=False)
    auth = TokenAuth(token_env="GG_TEST_TOKEN", token_file="/definitely/missing/token")
    with pytest.raises(SecretError, match="no token found"):
        resolve_token(auth)


def test_resolve_token_surfaces_unreadable_token_files(tmp_path, monkeypatch):
    monkeypatch.delenv("GG_TEST_TOKEN", raising=False)
    # A directory is unreadable-as-a-file without being NotFound.
    auth = TokenAuth(token_env="GG_TEST_TOKEN", token_file=str(tmp_path))
    with pytest.raises(SecretError, match="reading token file"):
        resolve_token(auth)


def test_token_file_path_prefers_env_then_default(monkeypatch):
    auth = TokenAuth(
        token_env="T", token_file_env="GG_TEST_TOKEN_PATH", token_file="~/.vault-token"
    )
    monkeypatch.delenv("GG_TEST_TOKEN_PATH", raising=False)
    assert token_file_path(auth) == "~/.vault-token"
    monkeypatch.setenv("GG_TEST_TOKEN_PATH", "/custom/token")
    assert token_file_path(auth) == "/custom/token"


def test_auth_headers_prepends_the_scheme(monkeypatch):
    monkeypatch.setenv("GG_TEST_TOKEN", "fake-token")
    auth = TokenAuth(token_env="GG_TEST_TOKEN", header="Authorization", scheme="Bearer")
    assert auth_headers(auth) == {"Authorization": "Bearer fake-token"}


def test_secret_fields_splits_objects_and_wraps_scalars():
    fields = secret_fields({"A": "1", "B": 2, "C": True})
    assert fields == {"A": "1", "B": "2", "C": "true"}
    assert secret_fields("flat") == {"value": "flat"}
    assert secret_fields(
        [
            {"id": "username", "label": "USERNAME", "value": "fake-user"},
            {"id": "empty"},
        ]
    ) == {"USERNAME": "fake-user"}


def test_onepassword_path_resolution_and_field_updates():
    assert parse_path("dev/myapp") == ("dev", "myapp")
    with pytest.raises(SecretError, match="<vault>/<item>"):
        parse_path("dev/team/myapp")

    vaults = [{"id": "vault-id", "name": "dev"}]
    assert (
        resolve_id(
            vaults,
            kind="vault",
            query="dev",
            name_key="name",
            path="dev/myapp",
        )
        == "vault-id"
    )
    item = {"fields": [{"id": "api", "label": "API_KEY", "value": "old"}]}
    merge_item_fields(item, {"API_KEY": "new", "DB_URL": "fake://db"})
    assert item["fields"][0]["value"] == "new"
    remove_item_fields(item, ["API_KEY"])
    assert [field["label"] for field in item["fields"]] == ["DB_URL"]


def test_onepassword_requests_use_bearer_auth_and_segment_encoding(monkeypatch):
    monkeypatch.setenv("OP_CONNECT_HOST", "https://connect.example")
    monkeypatch.setenv("OP_CONNECT_TOKEN", "fake-connect-token")
    store = SecretStore(Provider.ONEPASSWORD)
    request = store._request(
        "read_secret", {"vault_id": "vault id", "item_id": "item/id"}
    )
    assert request.full_url == (
        "https://connect.example/v1/vaults/vault%20id/items/item%2Fid"
    )
    assert request.get_header("Authorization") == "Bearer fake-connect-token"


def test_dot_path_walks_nested_objects():
    body = {"data": {"data": {"K": "V"}}}
    assert dot_path(body, "data.data") == {"K": "V"}
    assert dot_path(body, "data.missing") is None


def test_truncate_marks_elision():
    assert _truncate("short", 10) == "short"
    assert _truncate("x" * 300, 4) == "xxxx… (300 chars total)"
