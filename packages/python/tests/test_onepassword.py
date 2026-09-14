"""Offline request-flow tests for the 1Password Connect provider."""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Sequence
from typing import Any

from gitguardian import Provider, SecretStore


class FakeResponse:
    def __init__(self, body: Any) -> None:
        self._body = json.dumps(body).encode()

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


class FakeOpener:
    def __init__(self, responses: Sequence[Any]) -> None:
        self._responses = iter(responses)
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, *, timeout: int) -> FakeResponse:
        del timeout
        self.requests.append(request)
        return FakeResponse(next(self._responses))


def configure_connect(monkeypatch) -> None:
    monkeypatch.setenv("OP_CONNECT_HOST", "https://connect.example")
    monkeypatch.setenv("OP_CONNECT_TOKEN", "fake-connect-token")


def test_reads_an_item_by_vault_and_item_name(monkeypatch):
    configure_connect(monkeypatch)
    opener = FakeOpener(
        [
            [{"id": "vault-id", "name": "dev"}],
            [{"id": "item-id", "title": "myapp"}],
            {"fields": [{"id": "api", "label": "API_KEY", "value": "fake-value"}]},
        ]
    )
    store = SecretStore(Provider.ONEPASSWORD, env_override=False)
    store._opener = opener

    fields = store.get_secrets("dev/myapp")

    assert fields["API_KEY"].expose() == "fake-value"
    assert [request.get_method() for request in opener.requests] == [
        "GET",
        "GET",
        "GET",
    ]
    assert opener.requests[-1].full_url.endswith("/v1/vaults/vault-id/items/item-id")
    assert all(
        request.get_header("Authorization") == "Bearer fake-connect-token"
        for request in opener.requests
    )


def test_creates_a_missing_item(monkeypatch):
    configure_connect(monkeypatch)
    opener = FakeOpener(
        [
            [{"id": "vault-id", "name": "dev"}],
            [],
            {"id": "created-item"},
        ]
    )
    store = SecretStore(Provider.ONEPASSWORD)
    store._opener = opener

    store.set_secrets("dev/myapp", {"API_KEY": "fake-value"})

    request = opener.requests[-1]
    assert request.get_method() == "POST"
    assert request.full_url.endswith("/v1/vaults/vault-id/items")
    assert json.loads(request.data) == {
        "vault": {"id": "vault-id"},
        "title": "myapp",
        "category": "SECURE_NOTE",
        "fields": [
            {
                "label": "API_KEY",
                "type": "CONCEALED",
                "value": "fake-value",
            }
        ],
    }
