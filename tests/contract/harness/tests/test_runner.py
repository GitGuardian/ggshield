"""Tests of one command run (no ggshield involved: a Python script stands in)."""

import sys
from pathlib import Path

from tests.contract.harness.mock_server import ReplayMockServer
from tests.contract.harness.runner import run
from tests.contract.harness.sandbox import CHECKS_PERMISSIONS
from tests.contract.harness.spec import Spec


SCRIPT = """
import os, sys
sys.stdout.write("\\x1b[32m" + os.getcwd() + "\\x1b[0m\\r\\n")
with open("out.txt", "w") as f:
    f.write("written")
sys.exit(3)
"""


def test_run_collects_cleaned_outputs_and_written_files(tmp_path: Path) -> None:
    """
    GIVEN a command that prints its working directory in colour with \\r\\n,
    writes a file and exits with 3
    WHEN it is run in a sandbox
    THEN the output is cleaned and uses placeholders, and the file is collected
    """
    outputs = run(
        Spec(command=[]),
        tmp_path / "test",
        [sys.executable, "-c", SCRIPT],
        ReplayMockServer([]),
        tmp_path / "sandbox",
    )

    assert outputs.exit_code == 3
    assert outputs.stdout == "{{work}}\n"
    assert outputs.stderr == ""
    assert outputs.written.files == {"work/out.txt": "written"}
    assert outputs.written.permissions == (
        {"work/out.txt": "0644"} if CHECKS_PERMISSIONS else {}
    )
    assert outputs.written.deleted == []
