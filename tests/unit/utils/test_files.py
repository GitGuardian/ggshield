import re
import tarfile
from io import BytesIO
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Set, Union

import pytest

from ggshield.core.tar_utils import get_empty_tar
from ggshield.utils.files import (
    ListFilesMode,
    is_path_excluded,
    list_files,
    url_for_path,
)
from tests.repository import Repository
from tests.unit.conftest import write_text


def test_get_empty_tar():
    # WHEN creating an empty tar
    empty_tar_bytes = get_empty_tar()
    tar_stream = BytesIO(empty_tar_bytes)

    # THEN the file is considered as a .tar
    assert tarfile.is_tarfile(tar_stream)

    # AND it contains no file
    with tarfile.open(fileobj=tar_stream, mode="w:gz") as tar:
        assert len(tar.getmembers()) == 0


@pytest.mark.parametrize(
    "path,regexes,excluded",
    [
        ("foo", {"foo"}, True),
        (Path("dir/foo"), {"foo"}, True),
    ],
)
def test_is_path_excluded(
    path: Union[str, Path], regexes: Set[str], excluded: bool
) -> None:
    regexes = {re.compile(x) for x in regexes}
    assert is_path_excluded(path, regexes) == excluded


def test_list_files_git_repo(tmp_path: Path):
    """
    GIVEN a git repo
    WHEN calling get_filepaths
    THEN it should return all the commited and staged files
    and ignore files in .gitignore

    IF ignore_git_staged is set to True
    THEN it should return only the commited files
    and ignore files in .gitignore

    IF include_git_unstaged is set to True
    THEN it should return all the commited, staged and unstaged files
    and ignore files in .gitignore
    """
    local_repo = Repository.create(tmp_path)

    ignored_file = local_repo.path / "ignored_file"
    ignored_file.write_text("ignored")
    committed_file = local_repo.path / "committed_file"
    committed_file.write_text("committed")
    staged_file = local_repo.path / "staged_file"
    staged_file.write_text("staged")
    unstaged_file = local_repo.path / "unstaged_file"
    unstaged_file.write_text("unstaged")

    gitignore = local_repo.path / ".gitignore"
    gitignore.write_text("ignored_file")

    local_repo.add(committed_file, gitignore)
    local_repo.create_commit("initial commit")

    local_repo.add(staged_file)

    assert set(
        list_files(
            paths=[local_repo.path],
            exclusion_regexes={},
            list_files_mode=ListFilesMode.GIT_COMMITTED_OR_STAGED,
        )
    ) == {committed_file, staged_file, gitignore}

    assert set(
        list_files(
            paths=[local_repo.path],
            exclusion_regexes={},
            list_files_mode=ListFilesMode.GIT_COMMITTED,
        )
    ) == {committed_file, gitignore}

    assert set(
        list_files(
            paths=[local_repo.path],
            exclusion_regexes={},
            list_files_mode=ListFilesMode.ALL_BUT_GITIGNORED,
        )
    ) == {committed_file, staged_file, unstaged_file, gitignore}


@pytest.mark.parametrize(
    ("file_path", "expected"),
    [("front/file1.png", True), ("ignore/file2.png", False), ("file3.png", True)],
)
def test_get_ignored_files(tmp_path, file_path, expected):
    """
    GIVEN a directory
    WHEN listing its content
    THEN subdirectories matching the exclusion regexes are not inspected
    """
    file_path = tmp_path / file_path
    write_text(filename=str(file_path), content="")

    file_paths = list_files(
        paths=[tmp_path],
        exclusion_regexes={re.compile("ignore/.*")},
        list_files_mode=ListFilesMode.GIT_COMMITTED_OR_STAGED,
    )

    expected_paths = {file_path} if expected else set()
    assert file_paths == expected_paths


@pytest.mark.parametrize(
    "path,expected_url",
    [
        (PurePosixPath("/simple/path"), "file:///simple/path"),
        (PureWindowsPath(r"c:\Windows"), "file:///c:/Windows"),
        (PurePosixPath("relative/path"), "relative/path"),
        (PureWindowsPath(r"relative\win\path"), "relative/win/path"),
        (PurePosixPath("/path/with spaces"), "file:///path/with%20spaces"),
        (PurePosixPath("/étoile"), "file:///%C3%A9toile"),
    ],
)
def test_url_for_path(path: PurePath, expected_url: str):
    url = url_for_path(path)
    assert url == expected_url


def test_get_gitignored_files(tmp_path):
    """
    GIVEN a file, that is in the .gitignore
    WHEN listing its content
    THEN an empty set is returned
    """
    Repository.create(tmp_path)
    file_full_path = tmp_path / "file.txt"
    write_text(filename=str(tmp_path / ".gitignore"), content="file.txt")
    write_text(filename=str(file_full_path), content="")

    file_paths = list_files(
        paths=[file_full_path],
        exclusion_regexes=set(),
        list_files_mode=ListFilesMode.ALL_BUT_GITIGNORED,
    )

    assert file_paths == set()
