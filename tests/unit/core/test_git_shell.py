import os

import pytest
from click import UsageError

from ggshield.core.git_shell import (
    check_git_dir,
    git,
    is_git_dir,
    is_valid_git_commit_ref,
)
from ggshield.secret.repo import cd


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
        with pytest.raises(UsageError):
            check_git_dir()
