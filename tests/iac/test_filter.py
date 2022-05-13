import re
import subprocess
from pathlib import Path

from ggshield.iac.filter import get_iac_files_from_paths


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


def test_get_iac_files_from_paths(tmp_path):
    """
    GIVEN files added to the temp path
    WHEN calling get_iac_files_from_paths
    THEN it returns all iac files
    """
    tmp_paths = [str(tmp_path / filename) for filename in FILE_NAMES]
    for path in tmp_paths:
        Path(path).write_text("something")

    files = get_iac_files_from_paths([str(tmp_path)], set(), True, True, True)
    assert len(files.files) == 10
    assert str(tmp_path / "file1.json") not in files.files
    assert str(tmp_path / "file2.json") in files.files


def test_get_iac_files_from_paths_excluded(tmp_path):
    """
    GIVEN files added to the temp path
    WHEN calling get_iac_files_from_paths with an excluded pattern
    THEN it returns all iac files expect the ones matching the excluded patterns
    """
    tmp_paths = [str(tmp_path / filename) for filename in FILE_NAMES]
    for path in tmp_paths:
        Path(path).write_text("something")

    files = get_iac_files_from_paths(
        [str(tmp_path)], {re.compile(r"file2")}, True, True, True
    )
    assert len(files.files) == 9
    assert str(tmp_path / "file2.json") not in files.files
    assert str(tmp_path / "file3.yaml") in files.files


def test_get_iac_files_from_paths_ignore_git(tmp_path):
    """
    GIVEN files added to the temp path, as a git directory
    WHEN calling get_iac_files_from_paths with ignore_git as True
    THEN it returns all iac files expect the ones mentionned in the .gitignore
    """
    tmp_paths = [str(tmp_path / filename) for filename in FILE_NAMES]
    for path in tmp_paths:
        Path(path).write_text("something")
    Path(str(tmp_path / ".gitignore")).write_text("file2.json")
    tmp_path_str = str(tmp_path)
    subprocess.run(["git", "init"], cwd=tmp_path_str)
    subprocess.run(["git", "add", "."], cwd=tmp_path_str)

    files = get_iac_files_from_paths([tmp_path_str], set(), True, True, True)
    assert len(files.files) == 9
    assert str(tmp_path / "file2.json") not in files.files
    assert str(tmp_path / "file3.yaml") in files.files
