import sqlite3
from pathlib import Path

import pytest

from ggshield.verticals.ai.agent_activity.readers import iter_jsonl, iter_sqlite_rows


def test_iter_jsonl_yields_each_line_as_raw_string(tmp_path: Path) -> None:
    f = tmp_path / "log.jsonl"
    f.write_text('{"a": 1}\n{"b": 2}\n')
    assert list(iter_jsonl(f)) == ['{"a": 1}', '{"b": 2}']


def test_iter_jsonl_preserves_content_verbatim_even_if_unparseable(
    tmp_path: Path,
) -> None:
    """No JSON parsing — every non-empty line is yielded as-is."""
    f = tmp_path / "log.jsonl"
    f.write_text('{"a": 1}\nnot-json\n  {"b": 2}  \n')
    assert list(iter_jsonl(f)) == ['{"a": 1}', "not-json", '  {"b": 2}  ']


def test_iter_jsonl_drops_blank_lines(tmp_path: Path) -> None:
    f = tmp_path / "log.jsonl"
    f.write_text('{"a": 1}\n\n   \n{"b": 2}\n')
    assert list(iter_jsonl(f)) == ['{"a": 1}', '{"b": 2}']


def test_iter_jsonl_missing_file_yields_nothing(tmp_path: Path) -> None:
    assert list(iter_jsonl(tmp_path / "absent.jsonl")) == []


@pytest.fixture
def kv_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "data.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE kv (key TEXT, value TEXT)")
    conn.executemany(
        "INSERT INTO kv (key, value) VALUES (?, ?)",
        [("a", "1"), ("b", "2"), ("c", "3")],
    )
    conn.commit()
    conn.close()
    return db_path


def test_iter_sqlite_rows_yields_dicts(kv_db: Path) -> None:
    rows = list(iter_sqlite_rows(kv_db, "SELECT key, value FROM kv ORDER BY key"))
    assert rows == [
        {"key": "a", "value": "1"},
        {"key": "b", "value": "2"},
        {"key": "c", "value": "3"},
    ]


def test_iter_sqlite_rows_passes_parameters(kv_db: Path) -> None:
    rows = list(iter_sqlite_rows(kv_db, "SELECT value FROM kv WHERE key = ?", ("b",)))
    assert rows == [{"value": "2"}]


def test_iter_sqlite_rows_missing_db_yields_nothing(tmp_path: Path) -> None:
    assert list(iter_sqlite_rows(tmp_path / "absent.db", "SELECT 1")) == []


def test_iter_sqlite_rows_opens_read_only(kv_db: Path) -> None:
    """Writes via the opened connection must not succeed."""
    rows = list(
        iter_sqlite_rows(kv_db, "INSERT INTO kv (key, value) VALUES ('x', 'y')")
    )
    assert rows == []
    conn = sqlite3.connect(kv_db)
    assert conn.execute("SELECT count(*) FROM kv WHERE key='x'").fetchone() == (0,)
    conn.close()
