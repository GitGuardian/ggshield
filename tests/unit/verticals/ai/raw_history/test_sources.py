import json
import sqlite3
from pathlib import Path
from typing import Iterable

import pytest

from ggshield.verticals.ai.raw_history.models import RawHistoryEvent
from ggshield.verticals.ai.raw_history.sources import (
    JSONHistorySource,
    JSONLHistorySource,
    SQLiteHistorySource,
)


def test_jsonl_source_yields_raw_lines_with_offsets_and_relative_path(
    tmp_path: Path,
) -> None:
    a = tmp_path / "a.jsonl"
    a.write_text('{"i": 1}\n{"i": 2}\n')

    class S(JSONLHistorySource):
        kind = "demo"

        def discover(self) -> Iterable[Path]:
            return [a]

    events = list(S().iter_events(agent_name="t", path_root=tmp_path))
    assert events == [
        RawHistoryEvent(
            agent_name="t",
            source_kind="demo",
            source_path="a.jsonl",
            record_offset="0",
            content='{"i": 1}',
        ),
        RawHistoryEvent(
            agent_name="t",
            source_kind="demo",
            source_path="a.jsonl",
            record_offset="1",
            content='{"i": 2}',
        ),
    ]


def test_jsonl_source_sanitize_strips_pii_fields(tmp_path: Path) -> None:
    f = tmp_path / "x.jsonl"
    f.write_text(
        '{"msg": "hello", "pii": "secret"}\n{"msg": "world", "pii": "other"}\n'
    )

    class S(JSONLHistorySource):
        kind = "demo"

        def discover(self) -> Iterable[Path]:
            return [f]

        def sanitize(self, record: str) -> str:  # type: ignore[override]
            data = json.loads(record)
            data.pop("pii", None)
            return json.dumps(data)

    events = list(S().iter_events(agent_name="t", path_root=tmp_path))
    assert [(e.record_offset, e.content) for e in events] == [
        ("0", '{"msg": "hello"}'),
        ("1", '{"msg": "world"}'),
    ]


def test_jsonl_source_default_sanitize_is_passthrough(tmp_path: Path) -> None:
    f = tmp_path / "x.jsonl"
    f.write_text('{"a": 1}\n')

    class S(JSONLHistorySource):
        kind = "demo"

        def discover(self) -> Iterable[Path]:
            return [f]

    [event] = list(S().iter_events(agent_name="t", path_root=tmp_path))
    assert event.content == '{"a": 1}'


def test_json_source_yields_one_record_per_file(tmp_path: Path) -> None:
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text('{"hello": "world"}')
    b.write_text("[1, 2, 3]")

    class S(JSONHistorySource):
        kind = "json_file"

        def discover(self) -> Iterable[Path]:
            return sorted(tmp_path.glob("*.json"))

    events = list(S().iter_events(agent_name="t", path_root=tmp_path))
    assert events == [
        RawHistoryEvent(
            agent_name="t",
            source_kind="json_file",
            source_path="a.json",
            record_offset="0",
            content='{"hello": "world"}',
        ),
        RawHistoryEvent(
            agent_name="t",
            source_kind="json_file",
            source_path="b.json",
            record_offset="0",
            content="[1, 2, 3]",
        ),
    ]


def test_sqlite_source_raises_without_key_columns(tmp_path: Path) -> None:
    """Forgetting key_columns is a footgun, so the base class refuses to fall back."""
    db = tmp_path / "x.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE t (k TEXT, v INTEGER)")
    conn.execute("INSERT INTO t VALUES ('a', 1)")
    conn.commit()
    conn.close()

    class S(SQLiteHistorySource):
        kind = "demo_rows"
        query = "SELECT k, v FROM t"

        def discover(self) -> Iterable[Path]:
            return [db]

    with pytest.raises(NotImplementedError, match="key_columns"):
        list(S().iter_events(agent_name="t", path_root=tmp_path))


def test_sqlite_source_uses_key_columns_for_offset(tmp_path: Path) -> None:
    """Single key column → record_offset is that column's value."""
    db = tmp_path / "x.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE kv (key TEXT, value TEXT)")
    conn.executemany("INSERT INTO kv VALUES (?, ?)", [("k1", "v1"), ("k2", "v2")])
    conn.commit()
    conn.close()

    class S(SQLiteHistorySource):
        kind = "demo_kv"
        query = "SELECT key, value FROM kv ORDER BY key"
        key_columns = ("key",)

        def discover(self) -> Iterable[Path]:
            return [db]

    events = list(S().iter_events(agent_name="t", path_root=tmp_path))
    assert [e.record_offset for e in events] == ["k1", "k2"]


def test_sqlite_source_composite_key_columns(tmp_path: Path) -> None:
    """Multiple key columns → record_offset is a tuple of their values, in order."""
    db = tmp_path / "x.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE t (a TEXT, b TEXT, v INTEGER)")
    conn.executemany("INSERT INTO t VALUES (?, ?, ?)", [("x", "1", 10), ("x", "2", 20)])
    conn.commit()
    conn.close()

    class S(SQLiteHistorySource):
        kind = "demo_composite"
        query = "SELECT a, b, v FROM t ORDER BY a, b"
        key_columns = ("a", "b")

        def discover(self) -> Iterable[Path]:
            return [db]

    events = list(S().iter_events(agent_name="t", path_root=tmp_path))
    assert [e.record_offset for e in events] == ['["x", "1"]', '["x", "2"]']


def test_sqlite_source_record_offset_override_still_wins(tmp_path: Path) -> None:
    """Subclasses may still override record_offset() for non-trivial cases."""
    db = tmp_path / "x.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE kv (key TEXT, value TEXT)")
    conn.execute("INSERT INTO kv VALUES ('k1', 'v1')")
    conn.commit()
    conn.close()

    class S(SQLiteHistorySource):
        kind = "demo_custom"
        query = "SELECT key, value FROM kv"

        def discover(self) -> Iterable[Path]:
            return [db]

        def record_offset(self, record: dict, index: int) -> str:  # type: ignore[override]
            return f"custom:{record['key']}"

    events = list(S().iter_events(agent_name="t", path_root=tmp_path))
    assert [e.record_offset for e in events] == ["custom:k1"]
