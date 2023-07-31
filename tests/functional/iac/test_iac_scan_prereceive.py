from pathlib import Path
from subprocess import CalledProcessError
from typing import Tuple

import pytest

from tests.conftest import _IAC_NO_VULNERABILITIES, _IAC_SINGLE_VULNERABILITY
from tests.repository import Repository


HOOK_CONTENT = """#!/usr/bin/env sh
ggshield iac scan pre-receive
"""

HOOK_CONTENT_ALL = """#!/usr/bin/env sh
ggshield iac scan pre-receive --all
"""


@pytest.fixture
def repo_with_hook(tmp_path: Path) -> Tuple[Repository, Repository]:
    return repo_with_hook_content(tmp_path=tmp_path, hook_content=HOOK_CONTENT)


@pytest.fixture
def repo_with_hook_all(tmp_path: Path) -> Tuple[Repository, Repository]:
    return repo_with_hook_content(tmp_path=tmp_path, hook_content=HOOK_CONTENT_ALL)


def repo_with_hook_content(tmp_path: Path, hook_content: str) -> Repository:
    """
    Helper function that initialize a repo with a remote.
    The remote contains the pre-receive with the corresponding hook content.

    :param tmp_path: the root path
    :param hook_content: the pre-receive hook content
    :return: the local Repository object
    """
    remote_repo = Repository.create(tmp_path / "remote", bare=True)
    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")

    hook_path = remote_repo.path / "hooks" / "pre-receive"
    hook_path.write_text(hook_content)
    hook_path.chmod(0o700)
    return local_repo


def test_iac_scan_prereceive(repo_with_hook) -> None:
    # GIVEN a repo and remote with pre-receive hook
    # WHEN I add a vulnerable file to my local repo
    vuln_file_name = "file1.tf"
    vuln_path = repo_with_hook.path / vuln_file_name

    vuln_path.write_text(_IAC_SINGLE_VULNERABILITY)

    repo_with_hook.add(str(vuln_path))
    repo_with_hook.create_commit()

    # WHEN I try to push
    # THEN the hook prevents the push
    with pytest.raises(CalledProcessError) as exc:
        repo_with_hook.push()

    # AND the error message contains the vulnerability details
    stderr = exc.value.stderr.decode()
    assert "1 new incident" in stderr
    assert vuln_file_name in stderr


def test_iac_scan_prereceive_no_vuln(repo_with_hook) -> None:
    # GIVEN a repo and remote with pre-receive hook
    # WHEN I add a non vulnerable IaC file to my local repo
    non_vuln_file_name = "file_no_vuln.tf"
    non_vuln_path = repo_with_hook.path / non_vuln_file_name

    non_vuln_path.write_text(_IAC_NO_VULNERABILITIES)

    repo_with_hook.add(str(non_vuln_path))
    repo_with_hook.create_commit()

    # WHEN I try to push
    # THEN the hook accepts the push
    repo_with_hook.push()


def test_iac_scan_prereceive_no_iac(repo_with_hook) -> None:
    # GIVEN a repo and remote with pre-receive hook
    # WHEN I add a non IaC file to my local repo
    non_iac_file_name = "file1.txt"
    non_iac_path = repo_with_hook.path / non_iac_file_name

    non_iac_path.write_text("Not an IaC file.")

    repo_with_hook.add(str(non_iac_path))
    repo_with_hook.create_commit()

    # WHEN I try to push
    # THEN the hook accepts the push
    repo_with_hook.push()


def test_iac_scan_prereceive_all(repo_with_hook_all) -> None:
    # GIVEN a repo and remote with pre-receive hook set with the --all option
    # WHEN I add a vulnerable file to my local repo
    vuln_file_name = "file1.tf"
    vuln_path = repo_with_hook_all.path / vuln_file_name

    vuln_path.write_text(_IAC_SINGLE_VULNERABILITY)

    repo_with_hook_all.add(str(vuln_path))
    repo_with_hook_all.create_commit()

    # WHEN I try to push
    # THEN the hook, set to scan all, prevents the push
    with pytest.raises(CalledProcessError) as exc:
        repo_with_hook_all.push()

    # AND the error message contains the leaked secret
    stderr = exc.value.stderr.decode()
    # testing the all variant of the output
    assert "1 incident detected" in stderr
    assert vuln_file_name in stderr


def test_iac_scan_prereceive_branch_without_new_commits(repo_with_hook) -> None:
    # GIVEN a repo and remote with pre-receive hook
    # WHEN I push a new branch with a single empty commit
    branch_name = "topic"
    repo_with_hook.create_branch(branch_name)
    repo_with_hook.create_commit()

    # WHEN I try to push the branch
    # THEN the hook does not crash
    repo_with_hook.push("-u", "origin", branch_name)
