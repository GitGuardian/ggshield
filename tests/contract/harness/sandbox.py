"""The temporary folders of one test run, and what the command changes in them.

    <root>/       {{tmp}}, also TMPDIR
      work/       {{work}}, the current directory
      home/       {{home}}
      config/     {{config}}
      cache/      {{cache}}
      data/       {{data}}

work, home, config and data are tracked: a test seeds them from its input
folders of the same name, and what the command writes there is recorded under
expected/files/<folder>/<path>. The cache is not: the harness writes there
itself (update_check.yaml) and ggshield keeps run-specific caches.

The command runs with umask 022, so file modes are the same on every machine.
Not checked on Windows (no POSIX modes).
"""

from __future__ import annotations

import os
import shutil
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Tuple

from .files import decode_text, write_utf8


TRACKED_FOLDERS = ("work", "home", "config", "data")

# File content and permission bits (e.g. 0o600)
FileState = Tuple[bytes, int]

# POSIX permissions exist: modes are recorded and compared
CHECKS_PERMISSIONS = os.name != "nt"

# umask the command runs with, so modes do not depend on the machine
COMMAND_UMASK = 0o022


@dataclass
class Sandbox:
    root: Path

    @property
    def work(self) -> Path:
        return self.root / "work"

    @property
    def home(self) -> Path:
        return self.root / "home"

    @property
    def config(self) -> Path:
        return self.root / "config"

    @property
    def cache(self) -> Path:
        return self.root / "cache"

    @property
    def data(self) -> Path:
        return self.root / "data"

    def tracked(self) -> Dict[str, Path]:
        return {name: self.root / name for name in TRACKED_FOLDERS}

    @classmethod
    def create(cls, root: Path) -> Sandbox:
        sandbox = cls(root)
        for path in [*sandbox.tracked().values(), sandbox.cache]:
            path.mkdir(parents=True)
        # ggshield checks GitHub for a newer version after most commands, unless it
        # did so in the last 24 hours. Pretend it just did, without touching the
        # command line (adding --no-check-for-updates would change the argv, which
        # the Rust dispatcher matches exactly).
        write_utf8(sandbox.cache / "update_check.yaml", f"check-at: {time.time()}\n")
        return sandbox

    def seed(self, test_folder: Path, expand: Callable[[str], str]) -> None:
        """Copy the test's input folders into the tracked folders of the same
        name, expanding placeholders in UTF-8 text files only."""
        for name, destination in self.tracked().items():
            source = test_folder / name
            if not source.is_dir():
                continue
            shutil.copytree(source, destination, dirs_exist_ok=True)
            for path in destination.rglob("*"):
                if not path.is_file():
                    continue
                data = path.read_bytes()
                if b"{{" not in data:
                    continue
                text = decode_text(data)
                if text is None:
                    continue  # binary file: copied as is
                path.write_bytes(expand(text).encode("utf-8"))

    def snapshot(self) -> Dict[str, FileState]:
        """Every file in the tracked folders, keyed `<folder>/<posix path>`."""
        files: Dict[str, FileState] = {}
        for name, root in self.tracked().items():
            for path in root.rglob("*"):
                if path.is_file():
                    files[f"{name}/{path.relative_to(root).as_posix()}"] = (
                        path.read_bytes(),
                        stat.S_IMODE(path.stat().st_mode),
                    )
        return files


def changes(
    before: Dict[str, FileState], after: Dict[str, FileState]
) -> Tuple[Dict[str, FileState], List[str]]:
    """Files created or changed (content or permissions), and files deleted,
    between two snapshots."""
    written = {key: state for key, state in after.items() if before.get(key) != state}
    deleted = sorted(key for key in before if key not in after)
    return written, deleted
