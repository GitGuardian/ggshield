"""Best-effort local cursors so we only ship NEW agent-activity records.

``ggshield ai discover --history`` re-reads every agent transcript on each run.
Re-uploading records we already sent (which the server then re-scans and
deduplicates) is wasteful, so we persist a per-source high-water mark: the index
of the last record we successfully shipped. On the next run, append-only sources
skip records at or below that mark.

This is purely an optimisation. The store is **fail-open**: if it is missing or
unreadable we simply re-send everything (the server deduplicates on its own
``event_hash``, so a lost cursor costs one redundant batch, never correctness).
Delete the file to force a full re-scan.

Cursors are scoped to the ``(instance, API key)`` pair, so pointing ggshield at
a different account or instance starts from a clean slate. The raw key is never
written: the scope is a hash of it.
"""

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict

from pygitguardian import GGClient

from ggshield.core.dirs import get_cache_dir


logger = logging.getLogger(__name__)

CURSOR_FILE_NAME = "agent_activity_cursors.json"

# Index meaning "nothing committed yet"; every real record index is >= 0.
NOTHING = -1


def scope_for(client: GGClient) -> str:
    """Return an opaque key binding cursors to one ``(instance, credential)``.

    Hashes ``base_uri`` + ``api_key`` so switching either resets the cursor,
    without ever storing the raw key on disk.
    """
    digest = hashlib.sha256(f"{client.base_uri}\n{client.api_key}".encode())
    return digest.hexdigest()[:16]


class CursorStore:
    """JSON map ``scope -> agent -> source_kind -> source_path -> last index``."""

    def __init__(self, path: Path, data: Dict[str, Any]) -> None:
        self.path = path
        self._data = data

    @classmethod
    def load(cls) -> "CursorStore":
        """Load the cursor file, falling back to an empty store on any error."""
        path = get_cache_dir() / CURSOR_FILE_NAME
        data: Dict[str, Any] = {}
        try:
            if path.is_file():
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    data = loaded
        except (OSError, ValueError) as exc:
            logger.warning("agent_activity: ignoring unreadable cursor file: %s", exc)
        return cls(path, data)

    def get(self, scope: str, agent: str, kind: str, source_path: str) -> int:
        """Return the last committed index for a source, or ``NOTHING``."""
        try:
            return int(self._data[scope][agent][kind][source_path])
        except (KeyError, TypeError, ValueError):
            return NOTHING

    def advance(
        self, scope: str, agent: str, kind: str, source_path: str, index: int
    ) -> None:
        """Move a source's mark forward to ``index`` (never backwards)."""
        node = (
            self._data.setdefault(scope, {}).setdefault(agent, {}).setdefault(kind, {})
        )
        node[source_path] = max(int(node.get(source_path, NOTHING)), int(index))

    def save(self) -> None:
        """Atomically write the store; best-effort (never raises)."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._data, f)
            os.replace(tmp, self.path)
        except OSError as exc:
            logger.warning("agent_activity: failed to save cursor file: %s", exc)
