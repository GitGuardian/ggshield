from pathlib import Path
from typing import List

import pytest

from tests.conftest import _IAC_SINGLE_VULNERABILITY
from tests.functional.utils import run_ggshield_iac_scan
from tests.repository import Repository


def test_iac_scan_all(tmp_path: Path) -> None:
    # GIVEN a folder containing a file with vulnerabilities
    test_file = tmp_path / "vulnerability.tf"
    test_file.write_text(_IAC_SINGLE_VULNERABILITY)

    # WHEN scanning it
    # THEN vulnerabilities are found
    args = ["all", str(tmp_path)]
    result = run_ggshield_iac_scan(*args, cwd=tmp_path, expected_code=1)

    # AND the output contains context about the vulnerable resource
    assert "aws_alb_listener" in result.stdout
    assert "vulnerability.tf" in result.stdout


def test_iac_scan_all_empty(tmp_path: Path) -> None:
    # GIVEN an git repository with no IaC file
    repo = Repository.create(tmp_path)

    tracked_file = tmp_path / "not_an_iac_file.md"
    tracked_file.write_text("Nothing to see here...")
    repo.add(tracked_file)

    repo.create_commit()

    # WHEN scanning it
    args = ["all", str(tmp_path)]
    result = run_ggshield_iac_scan(*args, cwd=tmp_path, expected_code=0)

    # THEN the scan was skipped
    assert "> No IaC files detected. Skipping." in result.stdout


def test_iac_scan_all_ignore_all(tmp_path: Path) -> None:
    # GIVEN an git repository with a single ignored IaC file
    repo = Repository.create(tmp_path)

    not_iac_file = tmp_path / "not_an_iac_file.md"
    not_iac_file.write_text("Nothing to see here...")
    repo.add(not_iac_file)

    iac_file_name = "should_not_appear.tf"

    tracked_file = tmp_path / iac_file_name
    tracked_file.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(tracked_file)

    repo.create_commit()

    # WHEN scanning it
    args = ["all", "--ignore-path", iac_file_name, str(tmp_path)]
    result = run_ggshield_iac_scan(*args, cwd=tmp_path, expected_code=0)

    # THEN the scan was skipped
    assert "> No IaC files detected. Skipping." in result.stdout


def test_iac_scan_all_only_tracked_iac(tmp_path: Path) -> None:
    # GIVEN a git repository with vulnerabilities
    # - in a tracked file
    # - in an untracked file
    repo = Repository.create(tmp_path)

    tracked_file = tmp_path / "should_appear.tf"
    tracked_file.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(tracked_file)

    untracked_file = tmp_path / "should_not_appear.tf"
    untracked_file.write_text(_IAC_SINGLE_VULNERABILITY)
    # Do NOT add this file to git
    # repo.add(untracked_file)

    repo.create_commit()

    # WHEN scanning it
    args = ["all", str(tmp_path)]
    result = run_ggshield_iac_scan(*args, cwd=tmp_path, expected_code=1)

    # THEN only the tracked file appears in the output
    assert "should_appear.tf" in result.stdout
    assert "should_not_appear.tf" not in result.stdout


@pytest.mark.parametrize("ignored_paths", (["file1.tf"], ["file1.tf", "file2.tf"]))
def test_iac_scan_all_ignore_path(tmp_path: Path, ignored_paths: List[str]) -> None:
    # GIVEN a git repository with vulnerabilities in 3 files
    repo = Repository.create(tmp_path)
    all_files = ["file1.tf", "file2.tf", "file3.tf"]

    for filename in all_files:
        file = tmp_path / filename
        file.write_text(_IAC_SINGLE_VULNERABILITY)
        repo.add(file)

    # WHEN scanning with --ignore-path option
    args: List[str] = ["all", str(tmp_path)]
    for path in ignored_paths:
        args.append("--ignore-path")
        args.append(path)
    result = run_ggshield_iac_scan(*args, cwd=tmp_path, expected_code=1)

    # THEN ignored files do not appear in result
    for filename in all_files:
        assert (filename in result.stdout) == (filename not in ignored_paths)
