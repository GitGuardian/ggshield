"""Expected output of a test: saving it (--record) and comparing with it.

    expected/
      expected.yaml   exit code, and how each output is compared
      stdout.json     stdout when it is JSON (pretty-printed, compared as data)
      stdout.txt      stdout otherwise
      stderr.txt      absent when stderr must be empty
      files/          files the command wrote: see expected_files.py

`expected.yaml`:

    exit_code: 0
    stdout: full                 # compared exactly with stdout.json or stdout.txt
    stderr:
      contains: [--recursive]    # hand-written: only these words must appear
    files: ...                   # written files: see expected_files.py
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

from . import expected_files
from .expected_files import CompareMode, WrittenFiles
from .files import read_utf8, write_utf8
from .text import canonical_json, diff, indent


STREAMS = ("stdout", "stderr")
# A stream's mode in expected.yaml: "full", or {"contains": [...]}
StreamMode = Union[str, Dict[str, List[str]]]


@dataclass
class Outputs:
    exit_code: int
    stdout: str
    stderr: str
    written: WrittenFiles = field(default_factory=WrittenFiles)


def _as_json(text: str) -> Optional[Any]:
    stripped = text.strip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        return json.loads(stripped)
    except ValueError:
        return None


def _load_spec(expected_dir: Path) -> Dict[str, Any]:
    spec_path = expected_dir / "expected.yaml"
    if not spec_path.exists():
        return {}
    return yaml.safe_load(read_utf8(spec_path)) or {}


def record(expected_dir: Path, outputs: Outputs) -> None:
    """Save outputs as the expected output. Hand-written `contains` modes are kept."""
    expected_dir.mkdir(parents=True, exist_ok=True)
    previous = _load_spec(expected_dir)
    spec: Dict[str, Any] = {"exit_code": outputs.exit_code}

    for stream in STREAMS:
        mode: StreamMode = previous.get(stream, CompareMode.FULL.value)
        spec[stream] = mode
        for suffix in (".json", ".txt"):
            (expected_dir / f"{stream}{suffix}").unlink(missing_ok=True)
        if mode != CompareMode.FULL:
            continue
        text = getattr(outputs, stream)
        if not text:
            continue  # absent file = must be empty
        data = _as_json(text)
        if data is not None:
            write_utf8(expected_dir / f"{stream}.json", canonical_json(data))
        else:
            write_utf8(expected_dir / f"{stream}.txt", text)

    spec.update(expected_files.record(expected_dir, outputs.written, previous))

    write_utf8(
        expected_dir / "expected.yaml",
        yaml.safe_dump(spec, sort_keys=False, default_flow_style=False),
    )


def compare(expected_dir: Path, outputs: Outputs) -> List[str]:
    """Return one readable failure section per output that does not match."""
    if not (expected_dir / "expected.yaml").exists():
        return [f"No expected output in {expected_dir}: record it with --record."]

    spec = _load_spec(expected_dir)
    failures = []

    expected_code = spec.get("exit_code")
    if expected_code != outputs.exit_code:
        failures.append(f"exit code: expected {expected_code}, got {outputs.exit_code}")

    for stream in STREAMS:
        actual = getattr(outputs, stream)
        mode: StreamMode = spec.get(stream, CompareMode.FULL.value)
        if mode == CompareMode.FULL:
            failure = _compare_full(expected_dir, stream, actual)
        elif isinstance(mode, dict) and CompareMode.CONTAINS in mode:
            failure = _compare_contains(stream, mode[CompareMode.CONTAINS], actual)
        else:
            failure = f"{stream}: unknown compare mode {mode!r} in expected.yaml"
        if failure:
            failures.append(failure)

    failures += expected_files.compare(expected_dir, outputs.written, spec)
    return failures


def _compare_full(expected_dir: Path, stream: str, actual: str) -> Optional[str]:
    json_path = expected_dir / f"{stream}.json"
    if json_path.exists():
        expected_data = json.loads(read_utf8(json_path))
        actual_data = _as_json(actual)
        if actual_data is None:
            return f"{stream}: expected JSON, got:\n{indent(actual or '<empty>')}"
        if canonical_json(actual_data) == canonical_json(expected_data):
            return None
        return f"{stream} (JSON, compared as data):\n" + diff(
            canonical_json(expected_data),
            canonical_json(actual_data),
            f"expected/{json_path.name}",
        )

    txt_path = expected_dir / f"{stream}.txt"
    expected = read_utf8(txt_path) if txt_path.exists() else ""
    if actual == expected:
        return None
    return f"{stream}:\n" + diff(expected, actual, f"expected/{txt_path.name}")


def _compare_contains(stream: str, words: List[str], actual: str) -> Optional[str]:
    missing = [word for word in words if word not in actual]
    if not missing:
        return None
    return f"{stream}: missing {', '.join(repr(w) for w in missing)} in:\n" + indent(
        actual or "<empty>"
    )
