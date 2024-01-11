from pathlib import Path
from typing import List, Optional

import pytest

from tests.conftest import IAC_SINGLE_VULNERABILITY
from tests.functional.utils import run_ggshield_iac_scan
from tests.repository import Repository


# `iac scan` is set for deprecation, but should behave exactly as `iac scan all` in the meantime
pytestmark = pytest.mark.parametrize("scan_arg", ["all", None])


def _run_scan_iac(
    args: List[str], scan_arg: Optional[str], cwd: str, expected_code: int
):
    """
    Helper function to handle whether or not we are using the `all` subcommand.
    """
    if scan_arg is not None:
        args.insert(0, scan_arg)
    return run_ggshield_iac_scan(*args, cwd=cwd, expected_code=expected_code)


def test_iac_scan_all(tmp_path: Path, scan_arg) -> None:
    # GIVEN a folder containing a file with vulnerabilities
    test_file = tmp_path / "vulnerability.tf"
    test_file.write_text(IAC_SINGLE_VULNERABILITY)

    # WHEN scanning it
    # THEN vulnerabilities are found
    result = _run_scan_iac(
        args=[str(tmp_path)], scan_arg=scan_arg, cwd=tmp_path, expected_code=1
    )

    # AND the output contains context about the vulnerable resource
    assert "aws_alb_listener" in result.stdout
    assert "vulnerability.tf" in result.stdout


def test_iac_scan_all_empty(tmp_path: Path, scan_arg) -> None:
    # GIVEN an git repository with no IaC file
    repo = Repository.create(tmp_path)

    tracked_file = tmp_path / "not_an_iac_file.md"
    tracked_file.write_text("Nothing to see here...")
    repo.add(tracked_file)

    repo.create_commit()

    # WHEN scanning it
    result = _run_scan_iac(
        args=[str(tmp_path)], scan_arg=scan_arg, cwd=tmp_path, expected_code=0
    )

    # THEN the scan was skipped
    assert "Skipping" in result.stdout


def test_iac_scan_all_ignore_all(tmp_path: Path, scan_arg) -> None:
    # GIVEN an git repository with a single ignored IaC file
    repo = Repository.create(tmp_path)

    not_iac_file = tmp_path / "not_an_iac_file.md"
    not_iac_file.write_text("Nothing to see here...")
    repo.add(not_iac_file)

    iac_file_name = "should_not_appear.tf"

    tracked_file = tmp_path / iac_file_name
    tracked_file.write_text(IAC_SINGLE_VULNERABILITY)
    repo.add(tracked_file)

    repo.create_commit()

    # WHEN scanning it
    result = _run_scan_iac(
        args=["--ignore-path", iac_file_name],
        scan_arg=scan_arg,
        cwd=tmp_path,
        expected_code=0,
    )

    # THEN the scan was skipped
    assert "> No IaC files detected. Skipping." in result.stdout


def test_iac_scan_all_only_tracked_iac(tmp_path: Path, scan_arg) -> None:
    # GIVEN a git repository with vulnerabilities
    # - in a tracked file
    # - in an untracked file
    repo = Repository.create(tmp_path)

    tracked_file = tmp_path / "should_appear.tf"
    tracked_file.write_text(IAC_SINGLE_VULNERABILITY)
    repo.add(tracked_file)

    untracked_file = tmp_path / "should_not_appear.tf"
    untracked_file.write_text(IAC_SINGLE_VULNERABILITY)
    # Do NOT add this file to git
    # repo.add(untracked_file)

    repo.create_commit()

    # WHEN scanning it
    result = _run_scan_iac(
        args=[str(tmp_path)], scan_arg=scan_arg, cwd=tmp_path, expected_code=1
    )

    # THEN only the tracked file appears in the output
    assert "should_appear.tf" in result.stdout
    assert "should_not_appear.tf" not in result.stdout


@pytest.mark.parametrize("ignored_paths", (["file1.tf"], ["file1.tf", "file2.tf"]))
def test_iac_scan_all_ignore_path(
    tmp_path: Path, ignored_paths: List[str], scan_arg
) -> None:
    # GIVEN a git repository with vulnerabilities in 3 files
    repo = Repository.create(tmp_path)
    all_files = ["file1.tf", "file2.tf", "file3.tf"]

    for filename in all_files:
        file = tmp_path / filename
        file.write_text(IAC_SINGLE_VULNERABILITY)
        repo.add(file)

    # WHEN scanning with --ignore-path option
    args = [str(tmp_path)]
    for path in ignored_paths:
        args.append("--ignore-path")
        args.append(path)

    result = _run_scan_iac(args=args, scan_arg=scan_arg, cwd=tmp_path, expected_code=1)

    # THEN ignored files do not appear in result
    for filename in all_files:
        assert (filename in result.stdout) == (filename not in ignored_paths)


def test_iac_scan_all_subdir_content(
    tmp_path: Path,
    scan_arg: Optional[str],
) -> None:
    # GIVEN a git repository
    repo = Repository.create(tmp_path)
    repo.create_commit()

    # AND inner directory
    inner_dir_path = tmp_path / "inner" / "dir"
    inner_dir_path.mkdir(parents=True)

    # AND a first commit with vulnerabilities
    file1 = inner_dir_path / "file1.tf"
    file1.write_text(IAC_SINGLE_VULNERABILITY)
    repo.add(file1)
    repo.create_commit()

    # WHEN scanning the inner dir
    args = [str(inner_dir_path)]
    result = _run_scan_iac(args=args, scan_arg=scan_arg, cwd=tmp_path, expected_code=1)

    # THEN content is shown
    assert 'resource "aws_alb_listener" "bad_example"' in result.stdout
