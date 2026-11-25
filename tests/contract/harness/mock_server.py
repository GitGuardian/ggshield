"""Local stand-in for the GitGuardian API.

Replay mode answers from api_calls.yaml and checks every request. Record mode
(--record-api) forwards each request to the real API with the developer's key
and keeps the exchange; the caller scrubs it before saving api_calls.yaml.

It is a separate HTTP server, not an in-process patch, so it serves the Python
and the Rust implementation the same way.
"""

from __future__ import annotations

import json
import threading
from abc import ABC, abstractmethod
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, List

import requests

from .api_calls import (
    Call,
    Request,
    Response,
    check_headers,
    closest_entry,
    explain_mismatch,
)


# ggshield treats a localhost API URL as a self-hosted instance and prefixes
# API paths with this (ON_PREMISE_API_URL_PATH_PREFIX). api_calls.yaml stores paths
# without it, so they read the same whatever instance they were recorded on.
ON_PREMISE_PREFIX = "/exposed"

# Hop-by-hop or recomputed headers never copied to the client.
_SKIPPED_HEADERS = {
    "content-length",
    "transfer-encoding",
    "content-encoding",
    "connection",
}


class MockServer(ABC):
    """A local HTTP server standing in for the GitGuardian API. Subclasses
    decide how each request is answered."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Turns real values back into placeholders ({{work}}, ...) before a
        # request is matched or recorded. Set by the test once the sandbox and
        # the mock URL are known.
        self.normalize: Callable[[str], str] = lambda text: text

        server = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw_body = self.rfile.read(length) if length else b""
                uri = self.path
                if uri.startswith(ON_PREMISE_PREFIX + "/"):
                    uri = uri[len(ON_PREMISE_PREFIX) :]
                body = raw_body.decode("utf-8", "replace") if raw_body else None
                request = Request(
                    method=self.command,
                    uri=server.normalize(uri),
                    body=server.normalize(body) if body else None,
                    headers={
                        name: server.normalize(value)
                        for name, value in self.headers.items()
                    },
                )
                response = server._answer(request, uri, dict(self.headers), raw_body)
                # Standard reason phrase ("OK", "Not Found"); ggshield never reads it
                self.send_response(response.status)
                for name, value in response.headers.items():
                    if name.lower() not in _SKIPPED_HEADERS:
                        self.send_header(name, value)
                body = response.body.encode("utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _handle

            def log_message(self, format, *args):  # noqa: A002 - silence stderr
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        # `localhost`, not 127.0.0.1: ggshield only accepts a plain-HTTP API URL
        # for localhost (ggshield/core/url_utils.py, api_to_dashboard_url).
        port = self._httpd.server_address[1]
        return f"http://localhost:{port}"

    def __enter__(self) -> "MockServer":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        self._thread.join()

    @abstractmethod
    def _answer(
        self,
        request: Request,
        real_uri: str,
        headers: Dict[str, str],
        raw_body: bytes,
    ) -> Response:
        """The response to `request` (normalized); the raw parts are for
        forwarding."""


class ReplayMockServer(MockServer):
    """Answers from api_calls.yaml, and checks every request against it."""

    def __init__(self, calls: List[Call]):
        super().__init__()
        # Calls not made yet; a call is removed once a request matches it
        self._remaining = list(calls)
        self.errors: List[str] = []

    def _answer(
        self,
        request: Request,
        real_uri: str,
        headers: Dict[str, str],
        raw_body: bytes,
    ) -> Response:
        key = request.key()
        with self._lock:
            # Any unused call with the same content: calls may come in any
            # order (some run in parallel threads).
            for index, call in enumerate(self._remaining):
                if call.request.key() == key:
                    del self._remaining[index]
                    # Reported, but still answered: one wrong header should not
                    # cascade into unrelated failures
                    for error in check_headers(call.request, request):
                        self.errors.append(
                            f"{request.method.upper()} {request.uri}: {error}"
                        )
                    return call.response
            message = f"Request not in api_calls.yaml:\n  {request.describe()}"
            closest = closest_entry(request, [c.request for c in self._remaining])
            if closest is not None:
                message += (
                    "\nClosest entry in api_calls.yaml (same method and path):\n"
                    + explain_mismatch(request, closest)
                )
            self.errors.append(message)
        # 404 rather than 5xx: ggshield retries 5xx, which would only slow the
        # failure down.
        return Response(
            status=404,
            headers={"Content-Type": "application/json"},
            body=json.dumps(
                {"detail": "contract test mock: request not in api_calls.yaml"}
            ),
        )

    def unused(self) -> List[str]:
        """Errors for recorded calls the command never made."""
        return [
            f"Call in api_calls.yaml never made:\n  {call.request.describe()}"
            for call in self._remaining
        ]


class RecordMockServer(MockServer):
    """--record-api: forwards each request to the real API with the
    developer's key, and keeps the exchange. The caller scrubs it before
    saving api_calls.yaml."""

    def __init__(self, real_api_url: str, real_api_key: str):
        super().__init__()
        self._real_api_url = real_api_url.rstrip("/")
        self._real_api_key = real_api_key
        self.recorded: List[Call] = []

    def _answer(
        self,
        request: Request,
        real_uri: str,
        headers: Dict[str, str],
        raw_body: bytes,
    ) -> Response:
        # Forward the real request, record the normalized one
        forwarded = {
            k: v
            for k, v in headers.items()
            if k.lower() not in ("host", "content-length", "authorization")
        }
        forwarded["Authorization"] = f"Token {self._real_api_key}"
        real = requests.request(
            request.method,
            self._real_api_url + real_uri,
            headers=forwarded,
            data=raw_body or None,
            timeout=60,
        )
        response = Response(
            status=real.status_code,
            headers=dict(real.headers),
            body=real.text,
        )
        with self._lock:
            self.recorded.append(Call(request=request, response=response))
        return response
