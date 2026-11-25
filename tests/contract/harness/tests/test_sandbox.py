"""Tests of the sandbox: seeding and the written-files snapshot (no ggshield
involved)."""

import os
from pathlib import Path

import pytest

from tests.contract.harness.sandbox import Sandbox, changes


posix_only = pytest.mark.skipif(os.name == "nt", reason="no POSIX file modes")


def test_only_created_changed_and_deleted_files_are_reported(tmp_path: Path) -> None:
    """
    GIVEN a sandbox with files in work/ and config/, and one in the cache
    WHEN some are created, changed, deleted or left alone
    THEN only the differences are reported, and the cache is ignored
    """
    sandbox = Sandbox.create(tmp_path / "sandbox")
    (sandbox.work / "same.txt").write_text("same")
    (sandbox.work / "changed.txt").write_text("before")
    (sandbox.config / "removed.yaml").write_text("x: 1")
    before = sandbox.snapshot()

    (sandbox.work / "changed.txt").write_text("after")
    (sandbox.home / ".gitguardian.yaml").write_text("version: 2")
    (sandbox.config / "removed.yaml").unlink()
    (sandbox.cache / "auth_check.yaml").write_text("ignored")
    written, deleted = changes(before, sandbox.snapshot())

    assert {key: data for key, (data, _) in written.items()} == {
        "work/changed.txt": b"after",
        "home/.gitguardian.yaml": b"version: 2",
    }
    assert deleted == ["config/removed.yaml"]


@posix_only
def test_permission_only_change_counts_as_written(tmp_path: Path) -> None:
    """
    GIVEN a file in the sandbox
    WHEN only its permissions change
    THEN it is reported as written, with its new mode
    """
    sandbox = Sandbox.create(tmp_path / "sandbox")
    token_file = sandbox.config / "auth_config.yaml"
    token_file.write_text("instances: []")
    token_file.chmod(0o644)
    before = sandbox.snapshot()

    token_file.chmod(0o600)
    written, _ = changes(before, sandbox.snapshot())

    assert written == {"config/auth_config.yaml": (b"instances: []", 0o600)}


def test_seeded_file_is_reported_only_when_the_command_changes_it(
    tmp_path: Path,
) -> None:
    """
    GIVEN a file seeded into the sandbox from an input folder (config/)
    WHEN the command leaves it as is, then rewrites it
    THEN it is reported as written only after the rewrite
    """
    sandbox = Sandbox.create(tmp_path / "sandbox")
    seeded = tmp_path / "test" / "config"
    seeded.mkdir(parents=True)
    (seeded / "auth_config.yaml").write_text("instances: []\n")
    sandbox.seed(tmp_path / "test", lambda text: text)
    before = sandbox.snapshot()

    untouched, _ = changes(before, sandbox.snapshot())
    (sandbox.config / "auth_config.yaml").write_text("default_token_lifetime: 30\n")
    rewritten, _ = changes(before, sandbox.snapshot())

    assert untouched == {}
    assert list(rewritten) == ["config/auth_config.yaml"]
