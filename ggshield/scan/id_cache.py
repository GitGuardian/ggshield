import json
import logging
from pathlib import Path
from typing import Set


logger = logging.getLogger(__name__)


class IDCache:
    """
    Stores a list of IDs as JSON in self.cache_path.
    """

    def __init__(self, cache_path: Path):
        self.cache_path = cache_path
        self._ids: Set[str] = set()
        if self.cache_path.exists():
            self._load()

    def __contains__(self, id: str) -> bool:
        return id in self._ids

    def add(self, layer_id: str) -> None:
        self._ids.add(layer_id)
        self._save()

    def _load(self) -> None:
        try:
            ids = json.loads(self.cache_path.read_text())
        except Exception as exc:
            logger.warning("Failed to load cache from %s: %s", self.cache_path, exc)
            return
        self._ids = set(ids)

    def _save(self) -> None:
        text = json.dumps(list(self._ids))
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(text)
        except Exception as exc:
            logger.warning("Failed to save cache to %s: %s", self.cache_path, exc)
