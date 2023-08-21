import re
import subprocess
from pathlib import Path

import pytest

from ggshield.verticals.iac.filter import get_iac_files_from_path, is_iac_file_path


FILE_NAMES = [
    "file1.txt",
    "file2.json",
    "file3.yaml",
    "file4.yml",
    "file5.jinja",
    "file6.py",
    "file7.py.schema",
    "file8.jinja.schema",
    "file9.tf",
    "filetfvars.anything",
    "dockerfile.txt",
]


def test_get_iac_files_from_path(tmp_path):
    """
    GIVEN files added to the temp path
    WHEN calling get_iac_files_from_path
    THEN it returns all iac files
    """
    tmp_paths = [str(tmp_path / filename) for filename in FILE_NAMES]
    for path in tmp_paths:
        Path(path).write_text("something")

    files = get_iac_files_from_path(tmp_path, set(), True)
    assert len(files) == 9
    assert "file1.txt" not in files
    assert "file2.json" in files


def test_get_iac_files_from_path_excluded(tmp_path):
    """
    GIVEN files added to the temp path
    WHEN calling get_iac_files_from_path with an excluded pattern
    THEN it returns all iac files expect the ones matching the excluded patterns
    """
    tmp_paths = [str(tmp_path / filename) for filename in FILE_NAMES]
    for path in tmp_paths:
        Path(path).write_text("something")

    files = get_iac_files_from_path(tmp_path, {re.compile(r"file2")}, True)
    assert len(files) == 8
    assert "file2.json" not in files
    assert "file3.yaml" in files


@pytest.mark.parametrize("ignore_git", (False, True))
def test_get_iac_files_from_path_ignore_git(tmp_path, ignore_git):
    """
    GIVEN files added to the temp path, as a git directory
    WHEN calling get_iac_files_from_path with ignore_git
    THEN it returns all iac files added to git and not the ones mentioned in the
    .gitignore if ignore_git is True. Otherwise, it ignores the .gitignore
    """
    tmp_paths = [str(tmp_path / filename) for filename in FILE_NAMES]
    for path in tmp_paths:
        Path(path).write_text("something")
    Path(str(tmp_path / ".gitignore")).write_text("file2.json")
    tmp_path_str = str(tmp_path)
    subprocess.run(["git", "init"], cwd=tmp_path_str)
    subprocess.run(["git", "add", "."], cwd=tmp_path_str)

    # Assert the .git folder exists. files.files length assertion ensures it's not
    # included in the get_iac_files_from_path response
    assert Path(str(tmp_path / ".git")).exists()

    files = get_iac_files_from_path(tmp_path, set(), True, ignore_git)
    if ignore_git:
        assert len(files) == 9
        assert "file2.json" in files
    else:
        assert len(files) == 8
        assert "file2.json" not in files
        assert "file3.yaml" in files


def test_is_iac_file_path(tmp_path):
    assert is_iac_file_path(tmp_path / "file1.json")
    assert not is_iac_file_path(tmp_path / "file1.jpg")
