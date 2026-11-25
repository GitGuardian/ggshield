"""Files the command wrote: how they are stored in expected/ and compared.

    expected/files/<work|home|config|data>/<path>   files created or changed

and their entries in expected.yaml:

    files:                       # how each file is compared (kept on re-record)
      config/auth_config.yaml: data   # parsed (YAML/JSON) and compared as data
      work/notes.txt: full            # exact text (after placeholders)
    file_modes:                  # permissions (not on Windows)
      config/auth_config.yaml: '0600'
    deleted_files: [config/auth_config.yaml]   # only when the command deletes some

Text files get placeholders and \\n line endings, like outputs; binary files
are kept as bytes and compared byte for byte.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Union

import yaml

from .files import decode_text, write_utf8
from .sandbox import CHECKS_PERMISSIONS, FileState
from .text import canonical_json, diff, indent, unix_newlines


# Text content (placeholders applied) or raw bytes for binary files
Content = Union[str, bytes]


class CompareMode(str, Enum):
    """How an output is compared with expected/. Loaded from expected.yaml as
    plain strings, which compare equal to these members."""

    FULL = "full"  # exact text, after placeholders: streams and files
    DATA = "data"  # parsed YAML/JSON, compared as data: written files only
    CONTAINS = "contains"  # {contains: [words]}, hand-written: streams only


# Written files compared as data by default when recorded; others in full
DATA_EXTENSIONS = (".yaml", ".yml", ".json")

_PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")

# Files operating systems drop in folders on their own: never a recording
_OS_JUNK = {".DS_Store", "Thumbs.db", "desktop.ini"}


@dataclass
class WrittenFiles:
    # Files the command created or changed, keyed <folder>/<path>
    files: Dict[str, Content] = field(default_factory=dict)
    # Their permissions, e.g. {"config/auth_config.yaml": "0600"}
    # (`file_modes` in expected.yaml)
    permissions: Dict[str, str] = field(default_factory=dict)
    deleted: List[str] = field(default_factory=list)

    @classmethod
    def from_changes(
        cls,
        written: Dict[str, FileState],
        deleted: List[str],
        collapse: Callable[[str], str],
    ) -> WrittenFiles:
        return cls(
            files={
                key: _as_content(data, collapse) for key, (data, _) in written.items()
            },
            permissions=(
                {key: f"{mode:04o}" for key, (_, mode) in written.items()}
                if CHECKS_PERMISSIONS
                else {}
            ),
            deleted=deleted,
        )


def record(
    expected_dir: Path, written: WrittenFiles, previous: Dict[str, Any]
) -> Dict[str, Any]:
    """Save the files under expected/files/ and return their expected.yaml
    entries. Compare modes edited by hand in `previous` are kept."""
    files_dir = expected_dir / "files"
    if files_dir.exists():
        shutil.rmtree(files_dir)
    for key, content in written.files.items():
        path = files_dir / key
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            write_utf8(path, content)

    entries: Dict[str, Any] = {}
    previous_compare_modes = previous.get("files") or {}
    if written.files:
        entries["files"] = {
            key: previous_compare_modes.get(key, default_compare_mode(key))
            for key in sorted(written.files)
        }
    if written.permissions:
        entries["file_modes"] = dict(sorted(written.permissions.items()))
    if written.deleted:
        entries["deleted_files"] = written.deleted
    return entries


def compare(
    expected_dir: Path, written: WrittenFiles, spec: Dict[str, Any]
) -> List[str]:
    """Failures for written files: missing and unexpected files, then file by
    file (content, then permissions), then deletions."""
    files_dir = expected_dir / "files"
    recorded = _recorded_keys(files_dir)
    actual = set(written.files)
    failures = [
        f"file {key}: expected to be written, but was not"
        for key in sorted(recorded - actual)
    ]
    failures += [
        f"file {key}: written, but not expected:\n" + indent(_show(written.files[key]))
        for key in sorted(actual - recorded)
    ]
    compare_modes = spec.get("files") or {}
    expected_permissions = spec.get("file_modes") or {}
    for key in sorted(recorded & actual):
        mode = compare_modes.get(key, default_compare_mode(key))
        for failure in (
            _compare_content(
                key, (files_dir / key).read_bytes(), written.files[key], mode
            ),
            _compare_permissions(
                key, expected_permissions.get(key), written.permissions.get(key)
            ),
        ):
            if failure:
                failures.append(failure)
    expected_deleted = spec.get("deleted_files", [])
    if expected_deleted != written.deleted:
        failures.append(
            f"deleted files: expected {expected_deleted}, got {written.deleted}"
        )
    return failures


def default_compare_mode(key: str) -> str:
    """How a newly recorded file is compared: YAML and JSON as data."""
    mode = (
        CompareMode.DATA if key.lower().endswith(DATA_EXTENSIONS) else CompareMode.FULL
    )
    return mode.value  # a plain str: yaml.safe_dump refuses Enum members


def _as_content(data: bytes, collapse: Callable[[str], str]) -> Content:
    text = decode_text(data)
    if text is None:
        return data
    return collapse(unix_newlines(text))


def _canonical_data(text: str) -> Optional[str]:
    """YAML or JSON (JSON is YAML) as canonical JSON text, or None if it does
    not parse. Placeholders become plain words first: `path: {{work}}/a` is not
    valid YAML (an unquoted `{` starts a mapping)."""
    try:
        data = yaml.safe_load(_PLACEHOLDER.sub(r"__\1__", text))
    except yaml.YAMLError:
        return None
    return canonical_json(data)


def _recorded_keys(files_dir: Path) -> Set[str]:
    """The files recorded under expected/files/, keyed <folder>/<path>."""
    if not files_dir.is_dir():
        return set()
    return {
        p.relative_to(files_dir).as_posix()
        for p in files_dir.rglob("*")
        if p.is_file() and p.name not in _OS_JUNK
    }


def _compare_content(
    key: str, recorded: bytes, content: Content, mode: str
) -> Optional[str]:
    # Bytes first: the recording may be binary while the run wrote text
    if isinstance(content, bytes):
        return None if recorded == content else f"file {key}: binary content differs"
    recorded_text = decode_text(recorded)
    if recorded_text is None:
        return f"file {key}: expected binary content, got text:\n" + indent(content)
    if mode == CompareMode.DATA:
        return _compare_file_data(key, recorded_text, content)
    if mode == CompareMode.FULL:
        if recorded_text == content:
            return None
        return f"file {key}:\n" + diff(recorded_text, content, f"expected/files/{key}")
    return f"file {key}: unknown compare mode {mode!r} in expected.yaml"


def _compare_permissions(
    key: str, expected: Optional[str], actual: Optional[str]
) -> Optional[str]:
    if actual is None:
        return None  # not checked: Windows (no permissions collected)
    if expected is None:
        return f"file {key}: no mode recorded in expected.yaml, re-record with --record"
    if expected != actual:
        return f"file {key}: mode expected {expected}, got {actual}"
    return None


def _compare_file_data(key: str, recorded: str, actual: str) -> Optional[str]:
    expected_data, actual_data = _canonical_data(recorded), _canonical_data(actual)
    if expected_data is None:
        return f"file {key}: compared as data, but the recording is not valid YAML/JSON"
    if actual_data is None:
        return (
            f"file {key}: compared as data, but the written file is not valid"
            " YAML/JSON:\n" + indent(actual)
        )
    if expected_data == actual_data:
        return None
    return f"file {key} (compared as data):\n" + diff(
        expected_data, actual_data, f"expected/files/{key}"
    )


def _show(content: Content) -> str:
    if isinstance(content, bytes):
        return f"<{len(content)} bytes of binary content>"
    return content or "<empty>"
