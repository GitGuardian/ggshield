from pathlib import Path
from typing import Optional

import pytest

from ggshield.utils.git_shell import EMPTY_SHA
from tests.conftest import IAC_SINGLE_VULNERABILITY
from tests.functional.utils import run_ggshield_iac_scan
from tests.repository import Repository


@pytest.mark.parametrize(
    "scan_arg,file_content,expected_code,expected_output",
    [
        (None, "Nothing to see here", 0, "No new incident"),
        (None, IAC_SINGLE_VULNERABILITY, 1, "[+] 1 new incident detected (HIGH: 1)"),
        ("--all", "Nothing to see here", 0, "No incidents have been found"),
        ("--all", IAC_SINGLE_VULNERABILITY, 1, "1 incident detected"),
    ],
)
def test_ci_diff_no_vuln(
    tmp_path: Path,
    scan_arg: Optional[str],
    file_content: str,
    expected_code: int,
    expected_output: str,
) -> None:
    # GIVEN a repository
    repository = Repository.create(tmp_path)
    initial_sha = repository.create_commit()

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
    result = run_ggshield_iac_scan(
        *args,
        cwd=tmp_path,
        expected_code=expected_code,
        env={"GITLAB_CI": "1", "CI_COMMIT_BEFORE_SHA": initial_sha},
    )

    # THEN a vulnerability should be found if and only if
    # the committed file contains one
    assert "iac_file.tf" not in result.stdout
    assert ("test_file.tf" in result.stdout) == (
        file_content == IAC_SINGLE_VULNERABILITY
    )
    assert expected_output in result.stdout


def test_gitlab_previous_commit_sha_for_merged_results_pipelines(
    tmp_path: Path,
) -> None:
    # GIVEN a remote repository
    remote_repository = Repository.create(tmp_path / "remote", bare=True)
    # AND a local clone with a first vulnerability
    local_tmp_path = tmp_path / "local"
    repository = Repository.clone(remote_repository.path, local_tmp_path)
    ignored_file = local_tmp_path / "ignored_file.tf"
    ignored_file.write_text(IAC_SINGLE_VULNERABILITY)
    repository.add(ignored_file)
    repository.create_commit()
    repository.push()

    # AND a new commit containing another file with a vulnerability
    scanned_file = local_tmp_path / "scanned_file.tf"
    scanned_file.write_text(IAC_SINGLE_VULNERABILITY)
    repository.add(scanned_file)
    last_sha = repository.create_commit()

    # WHEN scanning it with the local last commit as CI_COMMIT_BEFORE_SHA var
    # to emulate Gitlab "merged results pipelines" behaviour
    args = ["ci"]
    result = run_ggshield_iac_scan(
        *args,
        cwd=local_tmp_path,
        expected_code=1,
        env={
            "GITLAB_CI": "1",
            "CI_COMMIT_BEFORE_SHA": last_sha,
            "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
        },
    )

    # THEN the scan should be run on the expected commit
    assert "ignored_file.tf" not in result.stdout
    assert "scanned_file.tf" in result.stdout
    assert "[+] 1 new incident detected (HIGH: 1)" in result.stdout


def test_gitlab_new_branch(tmp_path: Path) -> None:
    # GIVEN a remote repository
    remote_repository = Repository.create(tmp_path / "remote", bare=True)
    # AND a local clone with a vulnerability on the same branch
    repository = Repository.clone(remote_repository.path, tmp_path / "local")
    ignored_file = repository.path / "ignored_file.tf"
    ignored_file.write_text(IAC_SINGLE_VULNERABILITY)
    repository.add(ignored_file)
    repository.create_commit()
    repository.push()
    # AND another vulnerability on another branch
    repository.create_branch("branch2")
    scanned_file = repository.path / "scanned_file.tf"
    scanned_file.write_text(IAC_SINGLE_VULNERABILITY)
    repository.add(scanned_file)
    repository.create_commit()

    # WHEN scanning in CI on a push pipeline for a new branch
    result = run_ggshield_iac_scan(
        "ci",
        cwd=repository.path,
        expected_code=1,
        env={
            "GITLAB_CI": "1",
            "CI_COMMIT_BEFORE_SHA": EMPTY_SHA,
            "CI_COMMIT_BRANCH": "branch2",
        },
    )

    # THEN the scan should be run on the expected commit
    assert "ignored_file.tf" not in result.stdout
    assert "scanned_file.tf" in result.stdout
    assert "[+] 1 new incident detected (HIGH: 1)" in result.stdout


def test_gitlab_new_empty_branch(tmp_path: Path) -> None:
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

    # WHEN scanning in CI on a push pipeline for a new branch
    result = run_ggshield_iac_scan(
        "ci",
        cwd=repository.path,
        expected_code=0,
        env={
            "GITLAB_CI": "1",
            "CI_COMMIT_BEFORE_SHA": EMPTY_SHA,
            "CI_COMMIT_BRANCH": "branch2",
        },
    )

    # THEN the scan should be skipped
    assert "> No IaC files changed. Skipping." in result.stdout
