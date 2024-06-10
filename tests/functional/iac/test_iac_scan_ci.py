from pathlib import Path
from typing import Optional

import pytest

from tests.conftest import IAC_SINGLE_VULNERABILITY
from tests.functional.utils import run_ggshield_iac_scan
from tests.repository import Repository


@pytest.mark.parametrize(
    "scan_arg,file_content,expected_code,expected_output",
    [
        (None, "Nothing to see here", 0, "No incidents have been found"),
        (None, IAC_SINGLE_VULNERABILITY, 1, "[+] 1 new incident detected (HIGH: 1)"),
    ],
)
def test_scan_ci(
    tmp_path: Path,
    scan_arg: Optional[str],
    file_content: str,
    expected_code: int,
    expected_output: str,
) -> None:
    """
    GIVEN a repository, with a branch containing changes
    WHEN scanning it with ci
    THEN the changes are scanned
    """
    # GIVEN a repository
    repository = Repository.create(tmp_path)
    repository.create_commit()
    repository.create_commit()

    repository.create_branch("mr_branch")
    # AND a commit containing a file with or without a vulnerability
    test_file = tmp_path / "test_file.tf"
    test_file.write_text(file_content)
    repository.add(test_file)
    repository.create_commit()

    # AND an unstaged file with a vulnerability
    iac_file = tmp_path / "iac_file.tf"
    iac_file.write_text(IAC_SINGLE_VULNERABILITY)

    # WHEN scanning it
    args = ["ci"]
    if scan_arg is not None:
        args.append(scan_arg)
    args.append("--verbose")
    result = run_ggshield_iac_scan(
        *args,
        cwd=tmp_path,
        expected_code=expected_code,
        env={
            "GITLAB_CI": "1",
            "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
            "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "mr_branch",
        },
    )

    # THEN a vulnerability should be found if and only if
    # the committed file contains one
    assert "iac_file.tf" not in result.stdout
    assert ("test_file.tf" in result.stdout) == (
        file_content == IAC_SINGLE_VULNERABILITY
    )
    assert expected_output in result.stdout


def test_gitlab_new_empty_branch(tmp_path: Path) -> None:
    """
    GIVEN a repository, with a branch containing no new commit
    WHEN scanning it with scan ci
    THEN the scan is skipped
    """

    # GIVEN a remote repository
    remote_repository = Repository.create(tmp_path / "remote", bare=True)
    # AND a local clone with a vulnerability on the same branch
    repository = Repository.clone(remote_repository.path, tmp_path / "local")
    ignored_file = repository.path / "ignored_file.tf"
    ignored_file.write_text(IAC_SINGLE_VULNERABILITY)
    repository.add(ignored_file)
    repository.create_commit()
    repository.push()
    # AND another branch with no new commits
    repository.create_branch("branch2")
    repository.push("--set-upstream", "origin", "branch2")

    # WHEN scanning in CI on a push pipeline for a new branch
    result = run_ggshield_iac_scan(
        "ci",
        "--verbose",
        cwd=repository.path,
        expected_code=0,
        env={
            "GITLAB_CI": "1",
            "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
            "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "branch2",
        },
    )

    # THEN the scan should be skipped
    assert result.stdout == ""
    assert "No commit found in merge request, skipping scan." in result.stderr
