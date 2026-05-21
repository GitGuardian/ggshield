"""Tests for ggshield.core.plugin.http_security."""

import pytest
import requests

from ggshield.core.plugin.http_security import (
    INSECURE_LOOPBACK_ENV_VAR,
    LOOPBACK_HOSTS,
    assert_all_https,
    is_insecure_loopback_allowed,
    is_loopback,
)


class _CustomError(Exception):
    """Stand-in for the domain exceptions client.py / downloader.py raise."""


def _resp(*urls: str) -> requests.Response:
    """Build a Response whose history+url chain matches ``urls``.

    ``urls[-1]`` is the final response; everything before is a redirect hop.
    """
    final = requests.Response()
    final.url = urls[-1]
    final.history = []
    for u in urls[:-1]:
        hop = requests.Response()
        hop.url = u
        final.history.append(hop)
    return final


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "http://localhost:3000/x",
        "http://127.0.0.1:3000/x",
        "http://[::1]/x",
        "https://localhost/x",
    ],
)
def test_is_loopback_true(url: str) -> None:
    """is_loopback recognises every documented loopback host."""
    assert is_loopback(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/",
        "http://192.168.1.1/",
        "https://localhost.example.com/",  # subdomain attack
        "https://127.0.0.1.example.com/",
    ],
)
def test_is_loopback_false(url: str) -> None:
    """is_loopback rejects non-loopback hosts including lookalikes."""
    assert is_loopback(url) is False


def test_is_loopback_malformed_returns_false() -> None:
    """A non-URL string must not raise — just return False."""
    assert is_loopback("not a url") is False
    assert is_loopback("") is False


def test_loopback_hosts_constant_includes_v4_and_v6() -> None:
    assert "localhost" in LOOPBACK_HOSTS
    assert "127.0.0.1" in LOOPBACK_HOSTS
    assert "::1" in LOOPBACK_HOSTS


def test_is_insecure_loopback_allowed_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(INSECURE_LOOPBACK_ENV_VAR, raising=False)
    assert is_insecure_loopback_allowed() is False


def test_is_insecure_loopback_allowed_when_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(INSECURE_LOOPBACK_ENV_VAR, "1")
    assert is_insecure_loopback_allowed() is True


@pytest.mark.parametrize("value", ["", "0", "true", "yes", "TRUE"])
def test_is_insecure_loopback_allowed_only_accepts_one(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """Only the literal string ``"1"`` enables the bypass."""
    monkeypatch.setenv(INSECURE_LOOPBACK_ENV_VAR, value)
    assert is_insecure_loopback_allowed() is False


def test_assert_all_https_passes_for_https_only() -> None:
    response = _resp("https://example.com/a", "https://example.com/b")
    assert_all_https(response, exc_factory=_CustomError)  # no raise


def test_assert_all_https_rejects_http_final_hop() -> None:
    response = _resp("https://example.com/a", "http://example.com/b")
    with pytest.raises(_CustomError, match="Refusing insecure redirect"):
        assert_all_https(response, exc_factory=_CustomError)


def test_assert_all_https_rejects_http_intermediate_hop() -> None:
    response = _resp(
        "https://example.com/a",
        "http://evil.example.com/b",
        "https://example.com/c",
    )
    with pytest.raises(_CustomError):
        assert_all_https(response, exc_factory=_CustomError)


def test_assert_all_https_rejects_loopback_http_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(INSECURE_LOOPBACK_ENV_VAR, raising=False)
    response = _resp("https://example.com/a", "http://localhost:3000/b")
    with pytest.raises(_CustomError):
        assert_all_https(response, exc_factory=_CustomError)


def test_assert_all_https_allows_loopback_http_when_envvar_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(INSECURE_LOOPBACK_ENV_VAR, "1")
    response = _resp("https://example.com/a", "http://localhost:3000/b")
    assert_all_https(response, exc_factory=_CustomError)  # no raise


def test_assert_all_https_envvar_does_not_allow_arbitrary_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The env var must only widen loopback — not all of HTTP."""
    monkeypatch.setenv(INSECURE_LOOPBACK_ENV_VAR, "1")
    response = _resp("https://example.com/a", "http://example.com/b")
    with pytest.raises(_CustomError):
        assert_all_https(response, exc_factory=_CustomError)
