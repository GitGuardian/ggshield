"""api_calls.yaml: the API calls of a test, recorded once and replayed by the
mock server. Scrubbing before saving is in scrub.py.

Format:

    calls:
      - request:
          method: GET
          uri: /v1/health            # path and query, no host
          headers:                   # only these are checked; others ignored
            Authorization: Token {{api_key}}   # compared exactly
            User-Agent: '*'                    # must be present, any value
          body: null                 # text, or null
        response:
          status: 200
          headers: {Content-Type: application/json, X-App-Version: v0.0.0-test}
          body: '{"detail": "Valid API key."}'
"""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

import yaml

from .files import read_utf8, write_utf8
from .text import canonical_json, diff, indent


# Request header value meaning "must be present, any value"
ANY_VALUE = "*"


@dataclass
class Request:
    method: str
    uri: str
    body: Optional[str] = None
    # In api_calls.yaml: the headers checked (value, or ANY_VALUE). For an incoming
    # request: every header it was sent with.
    headers: Dict[str, str] = field(default_factory=dict)

    def key(self) -> Tuple[str, str, Tuple[Tuple[str, str], ...], str]:
        """What two requests must share to be the same request.

        Query parameters are compared as a sorted list, JSON bodies as data.
        """
        parts = urlsplit(self.uri)
        query = tuple(sorted(parse_qsl(parts.query, keep_blank_values=True)))
        return (self.method.upper(), parts.path, query, self.pretty_body())

    def path(self) -> str:
        return urlsplit(self.uri).path

    def query(self) -> Dict[str, List[str]]:
        params: Dict[str, List[str]] = {}
        for name, value in parse_qsl(urlsplit(self.uri).query, keep_blank_values=True):
            params.setdefault(name, []).append(value)
        return params

    def pretty_body(self) -> str:
        """The body as compared: JSON pretty-printed with sorted keys, else as is."""
        if not self.body:
            return ""
        try:
            return canonical_json(json.loads(self.body))
        except ValueError:
            return self.body if self.body.endswith("\n") else self.body + "\n"

    def describe(self) -> str:
        text = f"{self.method.upper()} {self.uri}"
        if self.body:
            text += "\n  body:\n" + indent(self.pretty_body())
        return text


def explain_mismatch(actual: Request, entry: Request) -> str:
    """What differs between a request and a recorded call with the same method
    and path: query parameters, then a diff of the bodies."""
    parts = []
    actual_query, entry_query = actual.query(), entry.query()
    for name in sorted(set(actual_query) | set(entry_query)):
        if actual_query.get(name) != entry_query.get(name):
            parts.append(
                f"query parameter {name!r}: recorded {entry_query.get(name)},"
                f" actual {actual_query.get(name)}"
            )
    if actual.pretty_body() != entry.pretty_body():
        parts.append(
            "body differs:\n"
            + diff(entry.pretty_body(), actual.pretty_body(), "api_calls.yaml")
        )
    return "\n".join(parts) or "no difference found in query or body"


def check_headers(entry: Request, actual: Request) -> List[str]:
    """Errors for the headers a recorded call lists that the request lacks or
    sends with another value. Headers the entry does not list are ignored."""
    sent = {name.lower(): value for name, value in actual.headers.items()}
    errors = []
    for name, expected in entry.headers.items():
        value = sent.get(name.lower())
        if value is None:
            errors.append(f"header {name} missing")
        elif expected != ANY_VALUE and value != expected:
            errors.append(f"header {name}: recorded {expected!r}, actual {value!r}")
    return errors


def closest_entry(request: Request, entries: List[Request]) -> Optional[Request]:
    """The entry with the same method and path whose body is the most similar."""
    candidates = [
        entry
        for entry in entries
        if entry.method.upper() == request.method.upper()
        and entry.path() == request.path()
    ]
    if not candidates:
        return None
    body = request.pretty_body()
    return max(
        candidates,
        key=lambda entry: difflib.SequenceMatcher(
            None, entry.pretty_body(), body
        ).ratio(),
    )


@dataclass
class Response:
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""


@dataclass
class Call:
    request: Request
    response: Response


def load(path: Path) -> List[Call]:
    """The calls in api_calls.yaml; no file means no API call expected."""
    if not path.exists():
        return []
    data = yaml.safe_load(read_utf8(path)) or {}
    calls = []
    for entry in data.get("calls", []):
        req, resp = entry["request"], entry["response"]
        calls.append(
            Call(
                request=Request(
                    method=req["method"],
                    uri=req["uri"],
                    body=req.get("body"),
                    headers={k: str(v) for k, v in (req.get("headers") or {}).items()},
                ),
                response=Response(
                    status=int(resp.get("status", 200)),
                    headers=dict(resp.get("headers") or {}),
                    body=resp.get("body") or "",
                ),
            )
        )
    return calls


def save(path: Path, calls: List[Call]) -> None:
    # Stable order: parallel calls arrive in any order
    ordered = sorted(calls, key=lambda call: call.request.key())
    data = {
        "calls": [
            {
                "request": {
                    "method": call.request.method,
                    "uri": call.request.uri,
                    "headers": dict(sorted(call.request.headers.items())),
                    "body": call.request.body,
                },
                "response": {
                    "status": call.response.status,
                    "headers": call.response.headers,
                    "body": call.response.body,
                },
            }
            for call in ordered
        ]
    }
    write_utf8(
        path, yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)
    )
