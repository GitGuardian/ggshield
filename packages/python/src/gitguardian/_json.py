"""JSON response helpers — the Python port of gitguardian-core's ``json.rs``."""

from __future__ import annotations

import json
from typing import Any, cast

from ._constants import SCALAR_FIELD_NAME


def secret_fields(value: Any) -> dict[str, str]:
    """Turn the extracted secret value into a map of field -> value.

    A JSON object becomes one entry per key, a 1Password-style field array
    uses each field's label/title/name/ID, and a scalar becomes one ``value``.
    """
    if isinstance(value, dict):
        fields = cast("dict[str, Any]", value)
        return {key: _scalar_to_string(item) for key, item in fields.items()}
    if isinstance(value, list):
        result: dict[str, str] = {}
        for raw in value:
            if not isinstance(raw, dict):
                continue
            field = cast("dict[str, Any]", raw)
            key = next(
                (
                    field[name]
                    for name in ("label", "title", "name", "id")
                    if isinstance(field.get(name), str)
                ),
                None,
            )
            if key is not None and "value" in field:
                result[key] = _scalar_to_string(field["value"])
        return result
    return {SCALAR_FIELD_NAME: _scalar_to_string(value)}


def _scalar_to_string(value: Any) -> str:
    """A JSON scalar as a plain string (no quotes); other shapes as JSON."""
    if isinstance(value, str):
        return value
    return json.dumps(value, separators=(",", ":"))


def dot_path(value: Any, path: str) -> Any:
    """Walk a dotted path (e.g. ``data.data``) into parsed JSON."""
    current: Any = value
    for segment in path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None
        current = cast("dict[str, Any]", current)[segment]
    return current
