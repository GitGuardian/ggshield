"""Scrubbing the API calls recorded with --record-api, before they are saved.

Rules live in tests/contract/scrub.yaml, shared by every test. Only listed
fields change; everything else stays as the real API returned it. Each real
value replaced in a response is remembered, and replaced by the same fake
value wherever a later request sent it back (URL, body, headers), so chained
calls, such as an ID from one response used in the next request, still match
on replay.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlsplit

import yaml

from .api_calls import ANY_VALUE, Call
from .files import read_utf8


# Response headers ggshield reads. Others are dropped when recording.
KEPT_RESPONSE_HEADERS = {
    "content-type",
    "x-app-version",
    "x-secrets-engine-version",
    "x-plugin-signature-url",
    "retry-after",
}

RULES_PATH = Path(__file__).parent.parent / "scrub.yaml"

# Real values shorter than this are not replaced in requests: a short value
# such as `12` would also hit unrelated text. None is chained by known commands.
MIN_MAPPED_VALUE_LENGTH = 4


def scrub(calls: List[Call]) -> List[Call]:
    """Replace personal and run-specific values (rules: scrub.yaml)."""
    rules = yaml.safe_load(read_utf8(RULES_PATH)) or {}
    header_rules = {
        k.lower(): v for k, v in (rules.get("response_headers") or {}).items()
    }
    json_rules: Dict[str, Dict[str, Any]] = rules.get("response_json") or {}
    request_rules = rules.get("request_headers") or {}
    exact = [p.lower() for p in request_rules.get("exact") or []]
    presence_only = [p.lower() for p in request_rules.get("presence_only") or []]

    mapping: Dict[str, str] = {}  # real value -> fake value, as text

    for call in calls:
        response = call.response
        headers = {}
        for name, value in response.headers.items():
            lower = name.lower()
            if lower not in KEPT_RESPONSE_HEADERS:
                continue
            if lower in header_rules:
                _remember(mapping, value, header_rules[lower])
                value = header_rules[lower]
            headers[name] = value
        response.headers = headers

        fields = json_rules.get(urlsplit(call.request.uri).path)
        if fields and response.body:
            try:
                payload = json.loads(response.body)
            except ValueError:
                payload = None
            if isinstance(payload, dict):
                for name, value in fields.items():
                    if name in payload:
                        _remember(mapping, payload[name], value)
                        payload[name] = value
                response.body = json.dumps(payload)

    for call in calls:
        request = call.request
        request.uri = _apply_mapping(request.uri, mapping)
        if request.body:
            request.body = _apply_mapping(request.body, mapping)
        kept = {}
        for name, value in request.headers.items():
            if _matches_any(name, exact):
                kept[name] = _apply_mapping(value, mapping)
            elif _matches_any(name, presence_only):
                kept[name] = ANY_VALUE
        request.headers = kept
    return calls


def _remember(mapping: Dict[str, str], real: Any, fake: Any) -> None:
    if real is None or isinstance(real, bool) or fake is None:
        return
    real_text, fake_text = str(real), str(fake)
    if real_text != fake_text and len(real_text) >= MIN_MAPPED_VALUE_LENGTH:
        mapping[real_text] = fake_text


def _apply_mapping(text: str, mapping: Dict[str, str]) -> str:
    """Replace whole values only: `1234` is not replaced inside `912345`."""
    for real in sorted(mapping, key=len, reverse=True):
        text = re.sub(
            rf"(?<![A-Za-z0-9_]){re.escape(real)}(?![A-Za-z0-9_])",
            lambda _, fake=mapping[real]: fake,
            text,
        )
    return text


def _matches_any(name: str, patterns: List[str]) -> bool:
    """Case-insensitive; a trailing * matches any suffix (GGShield-Machine-*)."""
    lower = name.lower()
    return any(
        lower.startswith(p[:-1]) if p.endswith("*") else lower == p for p in patterns
    )
