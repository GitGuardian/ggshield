import json
import sqlite3
from pathlib import Path
from typing import Iterable

import pytest

from ggshield.verticals.ai.agent_activity.models import AgentActivityEvent
from ggshield.verticals.ai.agent_activity.sources import (
    CONTENT_TRUNCATED_MARKER,
    MAX_CONTENT_BYTES,
    JSONActivitySource,
    JSONLActivitySource,
    SQLiteActivitySource,
    _elide_base64_blobs,
)


def test_jsonl_source_yields_raw_lines_with_offsets_and_relative_path(
    tmp_path: Path,
) -> None:
    a = tmp_path / "a.jsonl"
    a.write_text('{"i": 1}\n{"i": 2}\n')

    class S(JSONLActivitySource):
        kind = "demo"

        def discover(self) -> Iterable[Path]:
            return [a]

        def serialize(self, record: str) -> str:  # type: ignore[override]
            return record

    events = list(S().iter_events(agent_name="t", path_root=tmp_path))
    assert events == [
        AgentActivityEvent(
            agent_name="t",
            source_kind="demo",
            source_path="a.jsonl",
            record_offset="0",
            content='{"i": 1}',
        ),
        AgentActivityEvent(
            agent_name="t",
            source_kind="demo",
            source_path="a.jsonl",
            record_offset="1",
            content='{"i": 2}',
        ),
    ]


def test_jsonl_source_serialize_strips_pii_fields(tmp_path: Path) -> None:
    f = tmp_path / "x.jsonl"
    f.write_text(
        '{"msg": "hello", "pii": "secret"}\n{"msg": "world", "pii": "other"}\n'
    )

    class S(JSONLActivitySource):
        kind = "demo"

        def discover(self) -> Iterable[Path]:
            return [f]

        def serialize(self, record: str) -> str:  # type: ignore[override]
            data = json.loads(record)
            data.pop("pii", None)
            return json.dumps(data)

    events = list(S().iter_events(agent_name="t", path_root=tmp_path))
    assert [(e.record_offset, e.content) for e in events] == [
        ("0", '{"msg": "hello"}'),
        ("1", '{"msg": "world"}'),
    ]


def test_jsonl_source_ships_line_verbatim_by_default(tmp_path: Path) -> None:
    """The JSONL base ships each raw line unchanged (the client stays 'dumb')."""
    f = tmp_path / "x.jsonl"
    f.write_text('{"a": 1, "cmd": "ls -la"}\n')

    class S(JSONLActivitySource):
        kind = "demo"

        def discover(self) -> Iterable[Path]:
            return [f]

    [event] = list(S().iter_events(agent_name="t", path_root=tmp_path))
    assert event.content == '{"a": 1, "cmd": "ls -la"}'


def test_source_path_for_is_relative_to_path_root(tmp_path: Path) -> None:
    """The source path is relative to the agent's config dir (the dedup-key
    identifier); a path outside it falls back to its absolute form."""

    class S(JSONLActivitySource):
        kind = "demo"

        def discover(self) -> Iterable[Path]:
            return []

    inside = tmp_path / "projects" / "-repo" / "s.jsonl"
    assert S().source_path_for(inside, tmp_path) == "projects/-repo/s.jsonl"

    outside = tmp_path.parent / "elsewhere" / "rollout.jsonl"
    assert S().source_path_for(outside, tmp_path) == outside.as_posix()


def test_elide_base64_blobs_replaces_long_pure_base64() -> None:
    blob = "A" * 5000  # pure base64, over the threshold
    content = '{"type": "image", "media_type": "image/png", "data": "' + blob + '"}'
    out = _elide_base64_blobs(content)
    assert blob not in out
    assert "base64 elided" in out
    assert '"media_type": "image/png"' in out  # siblings preserved
    json.loads(out)  # still valid JSON


def test_elide_base64_blobs_keeps_short_values() -> None:
    content = '{"data": "' + "A" * 100 + '"}'  # below the threshold
    assert _elide_base64_blobs(content) == content


def test_elide_base64_blobs_spares_textual_fields() -> None:
    # A long stdout dump has whitespace/newlines, so it is not a pure base64 run.
    content = json.dumps({"stdout": "ls -la output line\n" * 500})
    assert _elide_base64_blobs(content) == content


def test_iter_events_elides_base64_in_shipped_content(tmp_path: Path) -> None:
    blob = "Zm9v" * 1500  # 6000 chars of pure base64
    f = tmp_path / "s.jsonl"
    f.write_text('{"type":"image","source":{"data":"' + blob + '"}}\n')

    class S(JSONLActivitySource):
        kind = "demo"

        def discover(self) -> Iterable[Path]:
            return [f]

    [event] = list(S().iter_events(agent_name="t", path_root=tmp_path))
    assert blob not in event.content
    assert "base64 elided" in event.content


def test_iter_events_caps_oversized_content(tmp_path: Path) -> None:
    """A record larger than MAX_CONTENT_BYTES is truncated with a marker."""
    f = tmp_path / "big.jsonl"
    f.write_text("x" * (MAX_CONTENT_BYTES + 5000) + "\n")

    class S(JSONLActivitySource):
        kind = "demo"

        def discover(self) -> Iterable[Path]:
            return [f]

        def serialize(self, record: str) -> str:  # type: ignore[override]
            return record

    [event] = list(S().iter_events(agent_name="t", path_root=tmp_path))
    assert event.content.endswith(CONTENT_TRUNCATED_MARKER)
    body = event.content[: -len(CONTENT_TRUNCATED_MARKER)]
    assert len(body.encode("utf-8")) <= MAX_CONTENT_BYTES


def test_json_source_yields_one_record_per_file(tmp_path: Path) -> None:
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text('{"hello": "world"}')
    b.write_text("[1, 2, 3]")

    class S(JSONActivitySource):
        kind = "json_file"

        def discover(self) -> Iterable[Path]:
            return sorted(tmp_path.glob("*.json"))

        def serialize(self, record: str) -> str:  # type: ignore[override]
            return record

    events = list(S().iter_events(agent_name="t", path_root=tmp_path))
    assert events == [
        AgentActivityEvent(
            agent_name="t",
            source_kind="json_file",
            source_path="a.json",
            record_offset="0",
            content='{"hello": "world"}',
        ),
        AgentActivityEvent(
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

    class S(SQLiteActivitySource):
        kind = "demo_rows"
        query = "SELECT k, v FROM t"

        def discover(self) -> Iterable[Path]:
            return [db]

        def serialize(self, record: object) -> str:  # type: ignore[override]
            return json.dumps(record)

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

    class S(SQLiteActivitySource):
        kind = "demo_kv"
        query = "SELECT key, value FROM kv ORDER BY key"
        key_columns = ("key",)

        def discover(self) -> Iterable[Path]:
            return [db]

        def serialize(self, record: object) -> str:  # type: ignore[override]
            return json.dumps(record)

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

    class S(SQLiteActivitySource):
        kind = "demo_composite"
        query = "SELECT a, b, v FROM t ORDER BY a, b"
        key_columns = ("a", "b")

        def discover(self) -> Iterable[Path]:
            return [db]

        def serialize(self, record: object) -> str:  # type: ignore[override]
            return json.dumps(record)

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

    class S(SQLiteActivitySource):
        kind = "demo_custom"
        query = "SELECT key, value FROM kv"

        def discover(self) -> Iterable[Path]:
            return [db]

        def record_offset(self, record: dict, index: int) -> str:  # type: ignore[override]
            return f"custom:{record['key']}"

        def serialize(self, record: object) -> str:  # type: ignore[override]
            return json.dumps(record)

    events = list(S().iter_events(agent_name="t", path_root=tmp_path))
    assert [e.record_offset for e in events] == ["custom:k1"]
