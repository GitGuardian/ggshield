"""Text helpers for comparing and showing outputs: canonical JSON, diffs."""

from __future__ import annotations

import difflib
import json
from typing import Any


def canonical_json(data: Any) -> str:
    """The one JSON form compared and shown everywhere: sorted keys, indent 2,
    non-ASCII kept. Compared as text, not Python values: in Python
    1 == 1.0 == True, which would hide a Rust output printing 200.0 or 1.
    `default=str` covers dates parsed from YAML."""
    return (
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False, default=str)
        + "\n"
    )


def diff(expected: str, actual: str, fromfile: str) -> str:
    """Unified diff, indented, of `fromfile` against the actual text."""
    lines = difflib.unified_diff(
        expected.splitlines(keepends=True),
        actual.splitlines(keepends=True),
        fromfile=fromfile,
        tofile="actual",
    )
    return indent(
        "".join(line if line.endswith("\n") else line + "\n" for line in lines)
    )


def indent(text: str, prefix: str = "    ") -> str:
    return "".join(f"{prefix}{line}\n" for line in text.splitlines())


def unix_newlines(text: str) -> str:
    return text.replace("\r\n", "\n")
