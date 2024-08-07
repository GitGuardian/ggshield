import inspect
from pathlib import Path
from typing import Set

import pytest
from pygitguardian import GGClient

from ggshield.core.scan.file import get_files_from_paths
from ggshield.verticals.sca.file_selection import (
    SCA_EXCLUSION_REGEXES,
    get_all_files_from_sca_paths,
    sca_files_from_git_repo,
)
from tests.repository import Repository
from tests.unit.conftest import my_vcr, write_text


# unsorted filenames
FILE_NAMES = [
    "backend/setup.cfg",
    "backend/pdm.lock",
    ".gitlab/ci/ci_scripts/pdm.lock",
    "front/yarn.lock",
    "backend/pyproject.toml",
    ".gitlab/ci/ci_scripts/pyproject.toml",
    "front/package.json",
    ".venv/dockerfile.txt",
]


def test_get_all_files_from_sca_paths(tmp_path):
    """
    GIVEN a directory
    WHEN calling get_all_files_from_sca_paths
    THEN we get the ones that are not excluded by is_excluded_from_sca in the right order
    """
    tmp_paths = [str(tmp_path / filename) for filename in FILE_NAMES]
    for path in tmp_paths:
        write_text(filename=path, content="")

    files = get_all_files_from_sca_paths(tmp_path, set(), True)
    assert len(files) == 7
    assert Path(".venv/dockerfile.txt") not in [Path(filepath) for filepath in files]
    assert Path("backend/pyproject.toml") in [Path(filepath) for filepath in files]
    assert Path("front/package.json") in [Path(filepath) for filepath in files]

    # test if the output is sorted
    assert files == [
        # we do this to handle windows paths
        str(Path(filename))
        for filename in [
            ".gitlab/ci/ci_scripts/pdm.lock",
            ".gitlab/ci/ci_scripts/pyproject.toml",
            "backend/pdm.lock",
            "backend/pyproject.toml",
            "backend/setup.cfg",
            "front/package.json",
            "front/yarn.lock",
        ]
    ]


@pytest.mark.parametrize(
    ("file_path", "expected"),
    [("front/file1.png", True), (".git/file2.png", False), ("file3.png", True)],
)
def test_get_ignored_files(tmp_path, file_path, expected):
    """
    GIVEN a directory
    WHEN calling sca scan a directory
    THEN excluded directory are not inspected
    """
    binary_path = tmp_path / file_path
    write_text(filename=str(binary_path), content="")

    _, binary_paths = get_files_from_paths(
        paths=[tmp_path],
        exclusion_regexes=SCA_EXCLUSION_REGEXES,  # directories we don't want to traverse
    )

    expected_paths = [binary_path] if expected else []
    assert binary_paths == expected_paths


@pytest.mark.parametrize(
    ("branch_name", "expected_files"),
    (
        ("branch_with_vuln", {Path("Pipfile"), Path("Pipfile.lock")}),
        ("branch_without_lock", {Path("Pipfile")}),
        ("branch_without_sca", set()),
    ),
)
def test_sca_files_from_git_repo(
    dummy_sca_repo: Repository,
    client: GGClient,
    branch_name: str,
    expected_files: Set[Path],
):
    """
    GIVEN a git repo and a ref
    WHEN calling sca_files_from_git_repo for this repo and ref
    THEN we get the expected filenames
    """

    fun_name = inspect.currentframe().f_code.co_name
    with my_vcr.use_cassette(f"{fun_name}_{branch_name}"):
        files = sca_files_from_git_repo(
            client=client, directory=dummy_sca_repo.path, ref=branch_name
        )
        assert files == expected_files


@my_vcr.use_cassette()
def test_sca_files_from_git_repo_with_staged_files(
    dummy_sca_repo: Repository, client: GGClient
):
    """
    GIVEN a git repo and a ref
    WHEN calling sca_files_from_git_repo for this repo and empty string as ref
    THEN we get the staged files
    """

    dummy_sca_repo.git("checkout", "branch_without_sca")
    (dummy_sca_repo.path / "package.json").touch()
    dummy_sca_repo.add("package.json")
    files = sca_files_from_git_repo(
        client=client, directory=dummy_sca_repo.path, ref=""
    )
    assert files == {Path("package.json")}
