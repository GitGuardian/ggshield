"""HTTPS-redirect guard shared by client.py and downloader.py.

Plugins are downloaded from at least three source types (GitGuardian
platform, GitHub artifacts, GitHub releases). All of them must reject
non-HTTPS redirect chains, but each layer wraps the failure in its own
domain exception. This module provides the primitive; callers pass the
exception factory.
"""

import os
from typing import Callable
from urllib.parse import urlparse

import requests


LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "[::1]", "::1"})
INSECURE_LOOPBACK_ENV_VAR = "GITGUARDIAN_ALLOW_INSECURE_LOOPBACK"


def is_loopback(url: str) -> bool:
    """Return True when ``url`` targets a loopback host."""
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return False
    return host in LOOPBACK_HOSTS


def is_insecure_loopback_allowed() -> bool:
    """Return True when the loopback HTTPS bypass is enabled.

    Read at call time so tests and QA harnesses can monkeypatch via
    ``monkeypatch.setenv``. Only the literal value ``"1"`` enables the
    bypass — any other value (including ``"true"``) is treated as off.
    """
    return os.environ.get(INSECURE_LOOPBACK_ENV_VAR) == "1"


def assert_all_https(
    response: "requests.Response",
    *,
    exc_factory: Callable[[str], Exception],
) -> None:
    """Reject non-HTTPS hops in the redirect chain.

    A non-HTTPS hop targeting a loopback host is allowed only when
    ``GITGUARDIAN_ALLOW_INSECURE_LOOPBACK=1`` is set. This is intended
    for local development and QA against an on-prem stack served on
    ``http://localhost:3000``; production deployments must leave the
    variable unset.

    ``exc_factory`` builds the exception to raise (e.g.
    ``PluginAPIError`` in ``client.py``, ``InsecureSourceError`` in
    ``downloader.py``). It MUST accept a single ``str`` argument.
    """
    allow_loopback = is_insecure_loopback_allowed()
    for hop in list(response.history) + [response]:
        if hop.url.startswith("https://"):
            continue
        if allow_loopback and is_loopback(hop.url):
            continue
        raise exc_factory(f"Refusing insecure redirect through {hop.url!r}")
