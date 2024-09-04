import subprocess
from pathlib import Path

import pytest

from ggshield.cmd.secret.scan.precommit import (
    check_is_merge_with_conflict,
    check_is_merge_without_conflict,
    get_merge_branch_from_reflog,
)
from tests.repository import Repository


def test_is_merge_not_merge(tmp_path):
    """
    GIVEN  a commit that is not a merge
    WHEN check_is_merge_with_conflict() or check_is_merge_without_conflict() is called
    THEN they return False
    """
    repo = Repository.create(tmp_path, initial_branch="master")

    Path(tmp_path / "inital.md").write_text("Initial")
    repo.add(".")
    repo.create_commit("Initial commit on master")

    assert not check_is_merge_without_conflict()
    assert not check_is_merge_with_conflict(cwd=tmp_path)


def test_is_merge_without_conflict(tmp_path, monkeypatch):
    """
    GIVEN  a merge commit without conflict
    WHEN check_is_merge_with_conflict() or check_is_merge_without_conflict() are called
    THEN they return the expected results
    """
    repo = Repository.create(tmp_path, initial_branch="master")
    repo.create_commit("Initial commit on master")

    repo.create_branch("feature_branch")
    repo.checkout("master")
    Path(tmp_path / "Other.md").write_text("Other")
    repo.add(".")
    repo.create_commit("Commit on master")

    repo.checkout("feature_branch")
    Path(tmp_path / "Another.md").write_text("Another")
    repo.add(".")
    repo.create_commit("Commit on feature_branch")

    monkeypatch.setenv("GIT_REFLOG_ACTION", "merge master")  # Simulate merge
    assert check_is_merge_without_conflict()
    assert not check_is_merge_with_conflict(cwd=tmp_path)


def test_is_merge_with_conflict(tmp_path):
    """
    GIVEN  a merge commit with conflict
    WHEN check_is_merge_with_conflict() or check_is_merge_without_conflict() are called
    THEN they return the expected results
    """
    repo = Repository.create(tmp_path, initial_branch="master")
    repo.create_commit("Initial commit on master")

    repo.create_branch("feature_branch")
    repo.checkout("master")
    conflict_file = tmp_path / "conflict.md"
    conflict_file.write_text("Hello")
    Path(tmp_path / "Other.md").write_text("Other")
    repo.add(".")
    repo.create_commit("Commit on master")

    repo.checkout("feature_branch")
    conflict_file.write_text("World")
    Path(tmp_path / "Another.md").write_text("Another")
    repo.add(".")
    repo.create_commit("Commit on feature_branch")

    # Create merge commit with conflict
    with pytest.raises(subprocess.CalledProcessError) as exc:
        repo.git("merge", "master")

    # check stdout for conflict message
    stdout = exc.value.stdout.decode()
    assert "CONFLICT" in stdout

    assert check_is_merge_with_conflict(cwd=tmp_path)
    assert not check_is_merge_without_conflict()

    # solve conflict but still counts as a merge with conflict
    conflict_file.write_text("Hello World !")
    repo.add(conflict_file)

    assert check_is_merge_with_conflict(cwd=tmp_path)
    assert not check_is_merge_without_conflict()


def test_get_merge_branch_from_reflog(monkeypatch):
    monkeypatch.setenv("GIT_REFLOG_ACTION", "merge master")  # Simulate merge
    assert check_is_merge_without_conflict()
    assert get_merge_branch_from_reflog() == "master"
