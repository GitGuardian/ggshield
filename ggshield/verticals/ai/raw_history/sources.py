"""History source abstraction.

A ``HistorySource`` is one logical source of raw records belonging to an agent
(e.g. "the JSONL session transcripts under ~/.claude/projects/*/*.jsonl").

The pipeline is three stages:
1. ``discover()``  — locate the files to read.
2. ``read(path)``  — yield raw records from one file.
3. ``sanitize(record)`` — strip PII fields and serialise the record to a string.

Each file's :meth:`source_path_for` returns the relative-to-root portion of
its path. Each record's :meth:`record_offset` returns its position within the
file (line index by default).

Subclasses fill in the parts they care about. The three concrete bases
(``JSONLHistorySource``, ``JSONHistorySource``, ``SQLiteHistorySource``) plug
``read`` in for the common cases; per-agent sources subclass ONE of them and
supply ``discover`` (+ optional ``sanitize``, optional ``record_offset`` override).
"""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar, Dict, Iterable, Iterator, Optional, Sequence, Tuple, Union

from ggshield.verticals.ai.raw_history.models import RawHistoryEvent
from ggshield.verticals.ai.raw_history.readers import iter_jsonl, iter_sqlite_rows


RawRecord = Union[str, Dict[str, object]]


class HistorySource(ABC):
    """Base class for a single raw-history source.

    Subclasses MUST set ``kind`` (the wire identifier) and implement
    ``discover``. ``sanitize``, ``source_path_for`` and ``record_offset`` have
    sensible defaults and only need overriding for sources that demand custom
    behaviour.
    """

    kind: ClassVar[str] = ""

    @abstractmethod
    def discover(self) -> Iterable[Path]:
        """Yield file paths to read."""

    @abstractmethod
    def read(self, path: Path) -> Iterator[RawRecord]:
        """Yield raw records from a single file."""

    def sanitize(self, record: RawRecord) -> str:
        """Strip PII fields from a record and serialise it to a string.

        Per-source overrides typically ``json.loads`` the raw line, drop
        PII-bearing keys, and return ``json.dumps`` of the trimmed dict.
        """
        assert isinstance(record, str), (
            f"{type(self).__name__}.sanitize received a non-string record; "
            "override sanitize() to handle this source's record type."
        )
        return record

    def source_path_for(self, path: Path, path_root: Optional[Path]) -> str:
        """Return the variable-suffix portion of ``path`` as a string.

        Default: the path relative to ``path_root`` (typically the agent's
        ``config_folder``). Sources whose files live outside the agent's config
        dir should override this method to strip a different prefix.
        """
        if path_root is not None:
            try:
                return str(path.relative_to(path_root))
            except ValueError:
                pass
        return str(path)

    def record_offset(self, record: RawRecord, index: int) -> str:
        """Identifier for ``record`` within its file.

        Receives the **raw record** from ``read()`` (before sanitizeing), so
        SQLite subclasses can inspect dict columns even after ``sanitize``
        stringifies the row.

        Default: the positional ``index`` serialised as a string (``"0"``, ``"1"``, …).
        Override when the record carries a natural unique ID.
        """
        return str(index)

    def iter_events(
        self, agent_name: str, path_root: Optional[Path] = None
    ) -> Iterator[RawHistoryEvent]:
        """Run the full discover → read → sanitize pipeline for this source."""
        for path in self.discover():
            source_path = self.source_path_for(path, path_root)
            for index, record in enumerate(self.read(path)):
                yield RawHistoryEvent(
                    agent_name=agent_name,
                    source_kind=self.kind,
                    source_path=source_path,
                    record_offset=self.record_offset(record, index),
                    content=self.sanitize(record),
                )


class JSONLHistorySource(HistorySource):
    """Source backed by a JSONL file. Yields one raw line per record."""

    def read(self, path: Path) -> Iterator[str]:
        yield from iter_jsonl(path)


class JSONHistorySource(HistorySource):
    """Source backed by a JSON file. Yields one record."""

    def read(self, path: Path) -> Iterator[str]:
        if not path.is_file():
            return
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        if text:
            yield text


class SQLiteHistorySource(HistorySource):
    """Source backed by a SQLite database.

    Subclasses MUST implement:
    - ``query`` — the SELECT to run per database (abstract property).
    - ``key_columns`` — the column(s) that uniquely identify a row (or override
      :meth:`record_offset` directly).

    Optional class variable:
    - ``params`` — bound parameters for ``query`` (default: no parameters).

    Why ``key_columns`` is required: there is no universal stable key across
    the supported databases — each table uses its own identifier (``id`` UUID,
    ``key`` string, or a composite pair of UUID columns). Some tables (e.g.
    Cursor's ``cursorDiskKV``) also insert rows of different types in
    interleaved order, so positional index is not reliable even within a
    single file.

    Subclasses that need something fancier can override :meth:`record_offset`
    directly, bypassing ``key_columns``.
    """

    query: ClassVar[str] = ""

    params: ClassVar[Sequence[Union[str, int, float, bytes, None]]] = ()
    key_columns: ClassVar[Tuple[str, ...]] = ()

    def read(self, path: Path) -> Iterator[Dict[str, object]]:
        yield from iter_sqlite_rows(path, self.query, self.params)

    def sanitize(self, record: RawRecord) -> str:
        """Serialise the row dict to a JSON string.

        Override to drop PII-bearing columns before serialising.
        """
        return json.dumps(record)

    def record_offset(self, record: RawRecord, index: int) -> str:
        """Build a stable string key from ``key_columns``.

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
