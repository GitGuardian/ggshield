"""Tests of one command run (no ggshield involved: a Python script stands in)."""

import sys
from pathlib import Path

import pytest

from tests.contract.harness.mock_server import ReplayMockServer
from tests.contract.harness.runner import SetupError, run
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


HEAD_SCRIPT = """
import subprocess, sys
sys.stdout.write(subprocess.check_output(["git", "rev-parse", "HEAD"], text=True))
"""


def _run_with_setup(setup, sandbox: Path):
    return run(
        Spec(command=[], setup=setup),
        sandbox.parent / "test",
        [sys.executable, "-c", HEAD_SCRIPT],
        ReplayMockServer([]),
        sandbox,
    )


def test_setup_builds_the_same_commit_on_every_run(tmp_path: Path) -> None:
    """
    GIVEN setup steps that create a repository with one commit
    WHEN the test is run twice
    THEN the command sees the same commit hash both times, and the
    repository created by setup is not reported as written
    """
    setup = [["git", "init"], ["git", "commit", "--allow-empty", "-m", "first"]]

    first = _run_with_setup(setup, tmp_path / "first")
    second = _run_with_setup(setup, tmp_path / "second")

    assert first.exit_code == 0, first.stderr
    assert len(first.stdout.strip()) == 40
    assert first.stdout == second.stdout
    assert first.written.files == {}


def test_failing_setup_step_is_reported(tmp_path: Path) -> None:
    """
    GIVEN a setup step that fails
    WHEN the test is run
    THEN SetupError names the step and shows git's output
    """
    with pytest.raises(SetupError) as error:
        _run_with_setup([["git", "commit", "-m", "no repository"]], tmp_path / "s")

    assert "['git', 'commit', '-m', 'no repository']" in str(error.value)
    assert "not a git repository" in str(error.value)
