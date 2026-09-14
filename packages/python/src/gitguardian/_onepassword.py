"""1Password Connect path resolution and item field helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, cast

from ._errors import SecretError, SecretNotFoundError, missing_fields_error


def parse_path(path: str) -> tuple[str, str]:
    """Parse the user-facing ``<vault>/<item>`` path."""
    vault, separator, item = path.partition("/")
    if not separator or not vault or not item or "/" in item:
        raise SecretError(f"path '{path}' must be '<vault>/<item>', e.g. dev/myapp")
    return vault, item


def resolve_id(
    values: Any, *, kind: str, query: str, name_key: str, path: str
) -> str | None:
    """Resolve an exact 1Password object name or ID from a list response."""
    if not isinstance(values, list):
        raise SecretError("1Password Connect list response was not an array")
    matches: list[tuple[str, str]] = []
    for raw in values:
        if not isinstance(raw, dict):
            continue
        value = cast("dict[str, Any]", raw)
        object_id = value.get("id")
        name = value.get(name_key)
        if isinstance(object_id, str) and (object_id == query or name == query):
            matches.append((object_id, name if isinstance(name, str) else ""))

    if not matches:
        if kind == "vault":
            raise SecretNotFoundError(f"secret not found at {path}")
        return None
    if len(matches) == 1:
        return matches[0][0]
    descriptions = ", ".join(
        f"{name} ({object_id})" if name else object_id for object_id, name in matches
    )
    raise SecretError(
        f"more than one 1Password {kind} matches '{query}'; "
        f"specify its ID: {descriptions}"
    )


def item_fields(fields: Mapping[str, str]) -> list[dict[str, str]]:
    """Convert a secret field map to Connect FullItem fields."""
    return [
        {"label": key, "type": "CONCEALED", "value": value}
        for key, value in fields.items()
    ]


def merge_item_fields(item: dict[str, Any], updates: Mapping[str, str]) -> None:
    """Merge secret fields into a Connect FullItem in place."""
    fields = _fields(item)
    for key, value in updates.items():
        field = next(
            (candidate for candidate in fields if _field_matches(candidate, key)),
            None,
        )
        if field is None:
            fields.append({"label": key, "type": "CONCEALED", "value": value})
        else:
            field["value"] = value


def replace_item_fields(item: dict[str, Any], fields: Mapping[str, str]) -> None:
    """Replace a Connect FullItem's fields in place."""
    item["fields"] = item_fields(fields)


def remove_item_fields(item: dict[str, Any], keys: Sequence[str]) -> None:
    """Remove named fields from a Connect FullItem in place."""
    fields = _fields(item)
    missing = [
        key for key in keys if not any(_field_matches(field, key) for field in fields)
    ]
    if missing:
        raise missing_fields_error(missing)
    item["fields"] = [
        field for field in fields if not any(_field_matches(field, key) for key in keys)
    ]


def _fields(item: dict[str, Any]) -> list[dict[str, Any]]:
    raw_fields = item.get("fields")
    if not isinstance(raw_fields, list) or not all(
        isinstance(field, dict) for field in raw_fields
    ):
        raise SecretError("1Password item response did not contain a fields array")
    return cast("list[dict[str, Any]]", raw_fields)


def _field_matches(field: Mapping[str, Any], key: str) -> bool:
    return any(field.get(attribute) == key for attribute in ("label", "title", "id"))
