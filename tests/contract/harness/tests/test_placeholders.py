"""Tests of the contract test placeholders (no ggshield involved)."""

from pathlib import Path

from tests.contract.harness.placeholders import Placeholders
from tests.contract.harness.sandbox import Sandbox


def test_nested_folders_get_their_own_placeholder(tmp_path: Path) -> None:
    """
    GIVEN placeholders for the sandbox root and the folders inside it
    WHEN an output mentions a path in a named folder and one directly in the root
    THEN the most specific placeholder wins, and the root catches the rest
    """
    sandbox = Sandbox.create(tmp_path / "sandbox")
    placeholders = Placeholders(
        {
            "work": str(sandbox.work),
            "cache": str(sandbox.cache),
            "tmp": str(sandbox.root),
        }
    )
    output = (
        f"{sandbox.work}/a.py\n"
        f"{sandbox.cache}/auth_check.yaml\n"
        f"{sandbox.root}/tmpfile\n"
    )

    assert placeholders.collapse(output) == (
        "{{work}}/a.py\n{{cache}}/auth_check.yaml\n{{tmp}}/tmpfile\n"
    )
