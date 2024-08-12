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


def test_get_iac_files_from_path(tmp_path: Path):
    """
    GIVEN files added to the temp path
    WHEN calling get_iac_files_from_path
    THEN it returns all iac files
    """
    for filename in FILE_NAMES:
        (tmp_path / filename).write_text("something")

    files = get_iac_files_from_path(tmp_path, set())
    assert len(files) == 9
    assert tmp_path / "file1.txt" not in files
    assert tmp_path / "file2.json" in files


def test_get_iac_files_from_path_excluded(tmp_path: Path):
    """
    GIVEN files added to the temp path
    WHEN calling get_iac_files_from_path with an excluded pattern
    THEN it returns all iac files expect the ones matching the excluded patterns
    """
    for filename in FILE_NAMES:
        (tmp_path / filename).write_text("something")

    files = get_iac_files_from_path(tmp_path, {re.compile(r"file2")})
    assert len(files) == 8
    assert tmp_path / "file2.json" not in files
    assert tmp_path / "file3.yaml" in files


@pytest.mark.parametrize("ignore_git", (False, True))
def test_get_iac_files_from_path_ignore_git(tmp_path: Path, ignore_git: bool):
    """
    GIVEN files added to the temp path, as a git directory
    WHEN calling get_iac_files_from_path with ignore_git
    THEN it returns all iac files added to git and not the ones mentioned in the
    .gitignore if ignore_git is True. Otherwise, it ignores the .gitignore
    """
    for filename in FILE_NAMES:
        (tmp_path / filename).write_text("something")
    (tmp_path / ".gitignore").write_text("file2.json")

    subprocess.run(["git", "init"], cwd=tmp_path)
    subprocess.run(["git", "add", "."], cwd=tmp_path)

    # Assert the .git folder exists. files.files length assertion ensures it's not
    # included in the get_iac_files_from_path response
    assert (tmp_path / ".git").exists()

    files = get_iac_files_from_path(tmp_path, set(), ignore_git)
    if ignore_git:
        assert len(files) == 9
        assert tmp_path / "file2.json" in files
    else:
        assert len(files) == 8
        assert tmp_path / "file2.json" not in files
        assert tmp_path / "file3.yaml" in files


def test_is_iac_file_path(tmp_path: Path):
    assert is_iac_file_path(tmp_path / "file1.json")
    assert not is_iac_file_path(tmp_path / "file1.jpg")
