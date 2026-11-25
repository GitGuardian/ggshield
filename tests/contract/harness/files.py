"""UTF-8, `\\n`-only file access, so recorded files are identical on every OS.

`Path.read_text` / `write_text` use the platform encoding (cp1252 on Windows)
and translate line endings; neither is acceptable for byte-exact recordings.
"""

from pathlib import Path
from typing import Optional


def read_utf8(path: Path) -> str:
    # newline="": no translation, a stray "\r\n" shows up instead of being hidden
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


def write_utf8(path: Path, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def decode_text(data: bytes) -> Optional[str]:
    """The UTF-8 text of a file, or None when it is binary (not valid UTF-8).
    The one rule deciding text vs binary: input files, written files, recordings."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None
