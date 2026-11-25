"""Run the command of one contract test once, and collect what comes out.

Each run gets a fresh sandbox, seeded from the test's input folders, and talks
to `server` (replaying api_calls.yaml, or recording against the real API). Outputs
are cleaned (colours, line endings) and real paths, the mock URL and the fake
key are turned back into placeholders.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import List

from .environment import build_env
from .expected import Outputs
from .expected_files import WrittenFiles
from .mock_server import MockServer
from .placeholders import Placeholders
from .sandbox import COMMAND_UMASK, Sandbox, changes
from .spec import Spec
from .text import unix_newlines


COMMAND_TIMEOUT = 120  # seconds

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def run(
    spec: Spec,
    test_folder: Path,
    ggshield: List[str],
    server: MockServer,
    sandbox_root: Path,
) -> Outputs:
    """Run `ggshield` + the test's arguments in a sandbox at `sandbox_root`."""
    sandbox = Sandbox.create(sandbox_root)
    with server as mock:
        placeholders = Placeholders.for_run(sandbox, mock.url)
        # Requests are matched and recorded with placeholders, as
        # api_calls.yaml stores them
        mock.normalize = placeholders.collapse
        sandbox.seed(test_folder, placeholders.expand)
        before = sandbox.snapshot()
        proc = subprocess.run(
            ggshield + placeholders.expand_value(spec.command),
            cwd=sandbox.work,
            env=build_env(sandbox, mock.url, placeholders.expand_value(spec.env)),
            input=placeholders.expand(spec.stdin).encode() if spec.stdin else b"",
            capture_output=True,
            timeout=COMMAND_TIMEOUT,
            umask=COMMAND_UMASK,  # Ignored on Windows
        )
        written, deleted = changes(before, sandbox.snapshot())

    def output(data: bytes) -> str:
        return placeholders.collapse(clean(data.decode("utf-8", "replace")))

    return Outputs(
        exit_code=proc.returncode,
        stdout=output(proc.stdout),
        stderr=output(proc.stderr),
        written=WrittenFiles.from_changes(written, deleted, placeholders.collapse),
    )


def clean(text: str) -> str:
    """Remove what never matters: colours and Windows line endings."""
    return _ANSI_ESCAPE.sub("", unix_newlines(text))
