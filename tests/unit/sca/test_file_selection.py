import inspect
import io
import tarfile
from typing import Set

import pytest
from pygitguardian import GGClient

from ggshield.sca.client import SCAClient
from ggshield.sca.file_selection import tar_sca_files_from_git_repo
from tests.repository import Repository
from tests.unit.conftest import my_vcr


@pytest.mark.parametrize(
    ("branch_name", "expected_files"),
    (
        ("branch_with_vuln", {"Pipfile", "Pipfile.lock"}),
        ("branch_without_lock", {"Pipfile"}),
        ("branch_without_sca", set()),
    ),
)
def test_tar_sca_files_from_git_repo(
    dummy_sca_repo: Repository,
    client: GGClient,
    branch_name: str,
    expected_files: Set[str],
):
    """
    GIVEN a git repo and a ref
    WHEN calling tar_sca_files_from_git_repo for this repo and ref
    THEN we have the expected filenames in the tar
    """

    fun_name = inspect.currentframe().f_code.co_name
    with my_vcr.use_cassette(f"{fun_name}_{branch_name}"):
        sca_client = SCAClient(client)
        tar_bytes = tar_sca_files_from_git_repo(
            client=sca_client, directory=dummy_sca_repo.path, ref=branch_name
        )
        tar_obj = tarfile.open(fileobj=io.BytesIO(tar_bytes))
        assert set(tar_obj.getnames()) == expected_files


@my_vcr.use_cassette()
def test_tar_sca_files_from_git_repo_with_staged_files(
    dummy_sca_repo: Repository, client: GGClient
):
    """
    GIVEN a git repo and a ref
    WHEN calling tar_sca_files_from_git_repo for this repo and empty string as ref
    THEN we have the staged files in the tar
    """

    sca_client = SCAClient(client)
    dummy_sca_repo.git("checkout", "branch_without_sca")
    (dummy_sca_repo.path / "package.json").touch()
    dummy_sca_repo.add("package.json")
    tar_bytes = tar_sca_files_from_git_repo(
        client=sca_client, directory=dummy_sca_repo.path, ref=""
    )
    tar_obj = tarfile.open(fileobj=io.BytesIO(tar_bytes))
    assert set(tar_obj.getnames()) == {"package.json"}
