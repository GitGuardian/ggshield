"""Activity source abstraction.

An ActivitySource is one logical source of raw records belonging to an agent
(e.g. "the JSONL session transcripts under ~/.claude/projects/*/*.jsonl").

The pipeline is three stages:
1. discover()  — locate the files to read.
2. read(path)  — yield raw records from one file.
3. serialize(record) — turn one record into the string shipped as the
   event content. The client is deliberately "dumb": it ships the agent's
   **raw** record verbatim (a JSONL line, or a serialised DB row) so the shape
   never depends on the ggshield version. GitGuardian scans the content and
   strips secrets server-side before storing it.

Each file's source_path_for returns the relative-to-root portion of
its path. Each record's record_offset returns its position within the
file (line index by default).

Subclasses fill in the parts they care about. The three concrete bases
(JSONLActivitySource, JSONActivitySource, SQLiteActivitySource) plug
read and a verbatim serialize in for the common cases; per-agent sources
usually only supply discover (+ optional record_offset override).
"""

import json
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar, Dict, Iterable, Iterator, Optional, Sequence, Tuple, Union

from ggshield.verticals.ai.agent_activity.models import AgentActivityEvent
from ggshield.verticals.ai.agent_activity.readers import iter_jsonl, iter_sqlite_rows


RawRecord = Union[str, Dict[str, object]]

# Cap a single record's content as a cheap defensive bound on payload size.
MAX_CONTENT_BYTES = 256 * 1024
CONTENT_TRUNCATED_MARKER = "…[ggshield: truncated]"

# A base64 run this long is a binary blob (an embedded image, a thinking-block
# signature, …) rather than meaningful text. Such blobs carry no analytical
# value, but they dominate the payload and waste the server-side secret scan, so
# we replace them with a short placeholder before shipping. Matching the base64
# character class (no whitespace) leaves textual fields like stdout untouched.
MIN_BASE64_ELIDE_CHARS = 4096
_BASE64_BLOB_RE = re.compile(r'"[A-Za-z0-9+/]{%d,}={0,2}"' % MIN_BASE64_ELIDE_CHARS)


def _elide_base64_blobs(content: str) -> str:
    """Replace long pure-base64 string values with a compact placeholder.

    Operates on the serialised record, so every other byte is shipped verbatim —
    only the oversized binary blob is swapped out, keeping its sibling metadata
    (media_type, etc.) intact.
    """

    def _replace(match: "re.Match[str]") -> str:
        # match includes the surrounding quotes; the blob itself is len - 2.
        return f'"<ggshield: {len(match.group(0)) - 2} bytes base64 elided>"'

    return _BASE64_BLOB_RE.sub(_replace, content)


def _cap_content(content: str) -> str:
    """Truncate content to MAX_CONTENT_BYTES (UTF-8), marking the cut."""
    encoded = content.encode("utf-8")
    if len(encoded) <= MAX_CONTENT_BYTES:
        return content
    return (
        encoded[:MAX_CONTENT_BYTES].decode("utf-8", errors="ignore")
        + CONTENT_TRUNCATED_MARKER
    )


class ActivitySource(ABC):
    """Base class for a single agent-activity source.

    Subclasses MUST set kind (the wire identifier) and implement
    discover. The format bases below also implement serialize (verbatim);
    source_path_for and record_offset have sensible defaults and only
    need overriding for sources that demand custom behaviour.
    """

    kind: ClassVar[str] = ""

    @abstractmethod
    def discover(self) -> Iterable[Path]:
        """Yield file paths to read."""

    @abstractmethod
    def read(self, path: Path) -> Iterator[RawRecord]:
        """Yield raw records from a single file."""

    def serialize(self, record: RawRecord) -> str:
        """Serialise one record to the string shipped as the event content.

        The format bases ship the record verbatim (the agent's raw line / row) —
        the client stays "dumb" so the shape never depends on the ggshield
        version. GitGuardian scans and strips secrets server-side before storing
        it. A source whose record type none of the format bases handle must
        implement this.
        """
        raise NotImplementedError(f"{type(self).__name__} must implement serialize().")

    def source_path_for(self, path: Path, path_root: Optional[Path]) -> str:
        """Return path relative to path_root (the agent's config dir).

        The result is a stable, config-relative identifier used as part of the
        record's dedup key (e.g. projects/<workspace>/<session>.jsonl). A
        path outside path_root — not expected for the registered sources —
        falls back to its absolute form. Always POSIX separators, so the shipped
        path is consistent regardless of the client OS.
        """
        if path_root is not None:
            try:
                return path.relative_to(path_root).as_posix()
            except ValueError:
                pass
        return path.as_posix()

    def record_offset(self, record: RawRecord, index: int) -> str:
        """Identifier for record within its file.

        Receives the **raw record** from read() (before serialising), so
        SQLite subclasses can inspect dict columns even after serialize
        stringifies the row.

        Default: the positional index serialised as a string ("00000", "00001", …).
        Keep leading zeros to avoid lexicographic sorting issues.
        Note that index counts the records read() actually yields (e.g.
        non-blank JSONL lines), not physical line numbers. Override when the
        record carries a natural unique ID.
        """
        return str(index).zfill(7)

    def iter_events(
        self, agent_name: str, path_root: Optional[Path] = None
    ) -> Iterator[AgentActivityEvent]:
        """Run the full discover → read → serialize pipeline for this source."""
        for path in self.discover():
            source_path = self.source_path_for(path, path_root)
            for index, record in enumerate(self.read(path)):
                content = _cap_content(_elide_base64_blobs(self.serialize(record)))
                yield AgentActivityEvent(
                    agent_name=agent_name,
                    source_kind=self.kind,
                    source_path=source_path,
                    record_offset=self.record_offset(record, index),
                    content=content,
                )


class JSONLActivitySource(ActivitySource):
    """Source backed by a JSONL file. Ships one raw line per record."""

    def read(self, path: Path) -> Iterator[str]:
        yield from iter_jsonl(path)

    def serialize(self, record: RawRecord) -> str:
        assert isinstance(record, str)
        return record


class JSONActivitySource(ActivitySource):
    """Source backed by a JSON file. Ships the raw file content as one record."""

    def read(self, path: Path) -> Iterator[str]:
        if not path.is_file():
            return
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        if text:
            yield text

    def serialize(self, record: RawRecord) -> str:
        assert isinstance(record, str)
        return record


class SQLiteActivitySource(ActivitySource):
    """Source backed by a SQLite database.

    Ships each row verbatim as a JSON object ({column: value, …}); secrets
    inside it are scanned and stripped server-side by GitGuardian.

    Subclasses MUST implement:
    - query — the SELECT to run per database (abstract property).
    - key_columns — the column(s) that uniquely identify a row (or override
      record_offset directly).

    Optional class variable:
    - params — bound parameters for query (default: no parameters).

    Why key_columns is required: there is no universal stable key across
    the supported databases — each table uses its own identifier (id UUID,
    key string, or a composite pair of UUID columns). Some tables (e.g.
    Cursor's cursorDiskKV) also insert rows of different types in
    interleaved order, so positional index is not reliable even within a
    single file.

    Subclasses that need something fancier can override record_offset
    directly, bypassing key_columns.
    """

    query: ClassVar[str] = ""

    params: ClassVar[Sequence[Union[str, int, float, bytes, None]]] = ()
    key_columns: ClassVar[Tuple[str, ...]] = ()

    def read(self, path: Path) -> Iterator[Dict[str, object]]:
        yield from iter_sqlite_rows(path, self.query, self.params)

    def serialize(self, record: RawRecord) -> str:
        return json.dumps(record)

    def record_offset(self, record: RawRecord, index: int) -> str:
        """Build a stable string key from key_columns.

        Single key column → that column's value as a string.
        Multiple key columns → a JSON-encoded list of their values, in order.
        """
        if not self.key_columns:
            raise NotImplementedError(
                f"{type(self).__name__} must set 'key_columns' (the column(s) "
                "uniquely identifying a row), or override record_offset() directly."
            )
        assert isinstance(record, dict)
        if len(self.key_columns) == 1:
            return str(record[self.key_columns[0]])
        return json.dumps([str(record[c]) for c in self.key_columns])
