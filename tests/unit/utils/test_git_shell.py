import os
import tarfile
from io import BytesIO
from pathlib import Path

import pytest

from ggshield.core.tar_utils import tar_from_ref_and_filepaths
from ggshield.utils.git_shell import (
    InvalidGitRefError,
    NotAGitDirectory,
    check_git_dir,
    check_git_ref,
    get_filepaths_from_ref,
    get_staged_filepaths,
    git,
    is_git_dir,
    is_valid_git_commit_ref,
)
from ggshield.utils.os import cd
from tests.repository import Repository


def test_git_shell():
    assert "usage: git" in git(["help"])


def test_is_git_dir(tmp_path):
    assert is_git_dir(os.getcwd())
    assert not is_git_dir(str(tmp_path))


def test_is_valid_git_commit_ref():
    assert is_valid_git_commit_ref("HEAD")
    assert not is_valid_git_commit_ref("invalid_ref")


def test_check_git_dir(tmp_path):
    """
    GIVEN a git checkout
    AND check_git_dir() has been called without arguments in it
    AND it did not raise an exception
    WHEN the current directory is changed to a directory which is not a git checkout
    AND check_git_dir() is called without arguments
    THEN it raises an exception

    (this tests the LRU cache on the functions in git_shell.py works correctly)
    """
    check_git_dir()

    with cd(str(tmp_path)):
        with pytest.raises(NotAGitDirectory):
            check_git_dir()


def test_check_git_ref_invalid_git_path(tmp_path):
    # WHEN checking a non git path
    with cd(str(tmp_path)):
        # THEN function throws an error
        with pytest.raises(NotAGitDirectory):
            check_git_ref(ref="HEAD")


def test_check_git_ref_valid_git_path(tmp_path):
    # GIVEN a remote repository
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    # AND a local clone
    local_repo_path = tmp_path / "local"
    local_repo = Repository.clone(remote_repo.path, local_repo_path)
    local_repo.create_commit()
    local_repo.push()

    # THEN valid git references do not throw
    check_git_ref("HEAD", local_repo_path)
    check_git_ref("@{upstream}", local_repo_path)

    # AND other strings throw
    with pytest.raises(InvalidGitRefError):
        check_git_ref("invalid_ref", local_repo_path)


def test_get_filepaths_from_ref(tmp_path):
    # GIVEN a repository
    repo = Repository.create(tmp_path)
    repo.create_commit()

    # AND a first commit
    first_file = repo.path / "first.py"
    first_content = "First file (included)"
    first_file.write_text(first_content)
    repo.add("first.py")
    repo.create_commit()

    # AND a second commit
    second_file = repo.path / "second.py"
    second_content = "Second file (not included)"
    second_file.write_text(second_content)
    repo.add("second.py")
    repo.create_commit()

    # WHEN scanning since the second commit
    filepaths = [str(path) for path in get_filepaths_from_ref("HEAD~1", tmp_path)]

    # THEN file from first commit is part of filepaths
    assert "first.py" in filepaths
    # AND file from second commit is not part of filepaths
    assert "second.py" not in filepaths


def test_get_staged_filepaths(tmp_path):
    # GIVEN a repository
    repo = Repository.create(tmp_path)
    repo.create_commit()

    # AND a first commit
    first_file = repo.path / "first.py"
    first_content = "First file (included)"
    first_file.write_text(first_content)
    repo.add("first.py")
    repo.create_commit()

    # AND staged content
    second_file = repo.path / "second.py"
    second_content = "Second file (included)"
    second_file.write_text(second_content)
    repo.add("second.py")

    # WHEN scanning for files, including staged
    filepaths = [str(path) for path in get_staged_filepaths(tmp_path)]

    # THEN file from first commit is part of filepaths
    assert "first.py" in filepaths
    # AND staged file is part of filepaths
    assert "second.py" in filepaths


def test_tar_from_ref_and_filepaths(tmp_path):
    # GIVEN a repository
    repo = Repository.create(tmp_path)
    repo.create_commit()

    first_file_name = "first.py"
    first_ignored_file_name = "first_ignored.py"
    second_file_name = "second.py"

    # AND a first commit
    first_file = repo.path / first_file_name
    first_content = "First file (included)"
    first_file.write_text(first_content)
    repo.add(first_file_name)

    first_ignored_file = repo.path / first_ignored_file_name
    first_ignored_content = "First file (filtered out)"
    first_ignored_file.write_text(first_ignored_content)
    repo.add(first_ignored_file_name)
    repo.create_commit()

    # AND a second commit
    second_file = repo.path / second_file_name
    second_content = "Second file (not included)"
    second_file.write_text(second_content)
    repo.add(second_file_name)
    repo.create_commit()

    # AND a list of filepaths
    filepaths = [first_file_name]

    # WHEN creating a tar
    tarbytes = tar_from_ref_and_filepaths(
        "HEAD~1", [Path(path_str) for path_str in filepaths], wd=tmp_path
    )

    tar_stream = BytesIO(tarbytes)
    with tarfile.open(fileobj=tar_stream, mode="r:gz") as tar:
        filenames = tar.getnames()
        # THEN only first file in in tar
        assert filenames == [first_file_name]
