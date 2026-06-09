"""Generic readers for raw history sources (JSONL files, SQLite tables)."""

import logging
import sqlite3
from pathlib import Path
from typing import Dict, Iterator, Sequence, Union


logger = logging.getLogger(__name__)


def iter_jsonl(path: Path) -> Iterator[str]:
    """Yield each non-blank line of a JSONL file as a raw string.

    Returns an empty iterator on I/O failure.
    """
    if not path.is_file():
        return
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.rstrip("\n").rstrip("\r")
                if not line.strip():
                    continue
                yield line
    except OSError:
        return


def iter_sqlite_rows(
    db_path: Path,
    query: str,
    params: Sequence[Union[str, int, float, bytes, None]] = (),
) -> Iterator[Dict[str, object]]:
    """Yield each row of query as a {column: value} dict.

    Missing DB/error → empty iterator.
    """
    if not db_path.is_file():
        return
    try:
        # immutable=1: editors (Cursor, VSCode) keep their SQLite DB open in WAL
        # mode, and a plain mode=ro connection then fails to open it ("unable to
        # open database file"). immutable lets us read the file as a static
        # snapshot regardless of the writer's lock; we never write back.
        conn = sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True)
    except sqlite3.Error as exc:
        logger.warning("iter_sqlite_rows: cannot open %s: %s", db_path, exc)
        return
    try:
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(query, params)
        except sqlite3.Error as exc:
            logger.warning("iter_sqlite_rows: query failed on %s: %s", db_path, exc)
            return
        try:
            for row in cursor:
                yield {key: row[key] for key in row.keys()}
        except sqlite3.Error as exc:
            logger.warning("iter_sqlite_rows: read failed on %s: %s", db_path, exc)
            return
    finally:
        conn.close()
