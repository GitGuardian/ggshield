import subprocess
from pathlib import Path

import pytest

from ggshield.__main__ import cli
from ggshield.cmd.secret.scan.precommit import (
    check_is_merge_with_conflict,
    check_is_merge_without_conflict,
    get_merge_branch_from_reflog,
)
from ggshield.utils.os import cd
from tests.repository import Repository
from tests.unit.conftest import assert_invoke_ok, my_vcr


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


@my_vcr.use_cassette("test_emoji_filename")
def test_precommit_with_emoji_filename(tmp_path, cli_fs_runner):
    """
    GIVEN a repository with a staged diff on a file with an emoji in its name
    WHEN the precommit command is run
    THEN it executes successfully
    """
    # Set up repository
    repo = Repository.create(tmp_path)

    # Create a file with emoji in the name
    emoji_file = tmp_path / "my_😊_emoji_file.txt"
    emoji_file.write_text("Initial content")
    repo.add(".")
    repo.create_commit("Initial commit with emoji file")

    # Modify the file and stage the changes
    emoji_file.write_text("Modified content")
    repo.add(".")

    # Run the precommit command
    with cd(repo.path):
        result = cli_fs_runner.invoke(cli, ["secret", "scan", "pre-commit"])
    # Verify the command executed successfully
    assert_invoke_ok(result)


@my_vcr.use_cassette("test_precommit_with_unmerged_files")
def test_precommit_with_unmerged_files(tmp_path, cli_fs_runner):
    """
    GIVEN a repository with a merge conflict containing unmerged files
    WHEN the precommit command is run
    THEN it executes successfully and scans the conflicted files
    """
    # Create repository with initial commit
    repo = Repository.create(tmp_path, initial_branch="master")
    repo.create_commit("Initial commit on master")

    # Create feature branch and add a file
    repo.create_branch("feature_branch")
    repo.checkout("master")
    conflict_file = tmp_path / "conflict.txt"
    conflict_file.write_text("Version from master")
    non_conflict_file = tmp_path / "no_conflict.txt"
    non_conflict_file.write_text("This file won't conflict")
    repo.add(".")
    repo.create_commit("Commit on master")

    # Switch to feature branch and create conflicting change
    repo.checkout("feature_branch")
    conflict_file.write_text("Version from feature")
    another_file = tmp_path / "feature.txt"
    another_file.write_text("New file from feature")
    repo.add(".")
    repo.create_commit("Commit on feature_branch")

    # Attempt merge which will create conflict
    with pytest.raises(subprocess.CalledProcessError) as exc:
        repo.git("merge", "master")

    # Verify we have a conflict
    stdout = exc.value.stdout.decode()
    assert "CONFLICT" in stdout

    # Resolve conflict and stage the resolution
    conflict_file.write_text("Resolved version")
    repo.add(conflict_file)

    # Run pre-commit scan on the merge with unmerged files
    with cd(repo.path):
        result = cli_fs_runner.invoke(cli, ["secret", "scan", "pre-commit"])

    # Verify the command executed successfully
    assert_invoke_ok(result)
