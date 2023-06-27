from pathlib import Path

import pytest

from tests.conftest import _IAC_SINGLE_VULNERABILITY
from tests.functional.utils import run_ggshield_iac_scan
from tests.repository import Repository


def test_iac_scan_diff_unchanged(tmp_path: Path) -> None:
    # GIVEN a git repository
    repo = Repository.create(tmp_path)
    repo.create_commit()

    # AND a first commit with vulnerabilities
    file1 = tmp_path / "file1.tf"
    file1.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(file1)
    file2 = tmp_path / "file2.tf"
    file2.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(file2)
    repo.create_commit()

    # WHEN scanning the diff between current and HEAD
    # (meaning both states should be the same)
    args = ["diff", "--ref", "HEAD", str(tmp_path)]
    result = run_ggshield_iac_scan(*args, cwd=tmp_path, expected_code=1)

    # THEN the output shows two unchanged vulnerabilities
    assert "0 incidents deleted" in result.stdout
    assert "2 incidents remaining" in result.stdout
    assert "0 new incidents detected" in result.stdout


def test_iac_scan_diff_new_vuln(tmp_path: Path) -> None:
    # GIVEN a git repository
    repo = Repository.create(tmp_path)
    repo.create_commit()

    # AND a first commit with a vulnerability in file1.tf
    file1 = tmp_path / "file1.tf"
    file1.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(file1)
    repo.create_commit()

    # AND a second commit with another vulnerability in file2.tf
    file2 = tmp_path / "file2.tf"
    file2.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(file2)
    repo.create_commit()

    # WHEN scanning the diff between current and HEAD~1
    # (meaning reference should be one commit behind)
    args = ["diff", "--ref", "HEAD~1", str(tmp_path)]
    result = run_ggshield_iac_scan(*args, cwd=tmp_path, expected_code=1)

    print(result.stdout)
    # THEN vulnerability of file1.tf shows as unchanged
    # AND vulnerability of file2.tf shows as new
    assert "0 incidents deleted" in result.stdout
    assert "1 incident remaining" in result.stdout
    assert "1 new incident detected" in result.stdout
    # AND details about the new vulnerability are shown
    assert "file2.tf" in result.stdout


def test_iac_scan_diff_removed_vuln(tmp_path: Path) -> None:
    # GIVEN a git repository
    repo = Repository.create(tmp_path)
    repo.create_commit()

    # AND a first commit with a vulnerability in file1.tf and file2.tf
    file1 = tmp_path / "file1.tf"
    file1.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(file1)

    file2 = tmp_path / "file2.tf"
    file2.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(file2)
    repo.create_commit()

    # AND a second commit removing the vulnerability in file1.tf
    file1.write_text("")
    repo.add(file1)
    repo.create_commit()

    # WHEN scanning the diff between current and HEAD~1
    # (meaning reference should be one commit behind)
    args = ["diff", "--ref", "HEAD~1", str(tmp_path)]
    result = run_ggshield_iac_scan(*args, cwd=tmp_path, expected_code=1)

    # THEN the output contains the vulnerability of file2.tf as unchanged
    # AND the output contains the vulnerability of file1.tf as deleted
    assert "1 incident deleted" in result.stdout
    assert "1 incident remaining" in result.stdout
    assert "0 new incidents detected" in result.stdout


def test_iac_scan_diff_only_tracked_iac(tmp_path: Path) -> None:
    # GIVEN a git repository with vulnerabilities
    # - in a tracked file
    # - in an untracked file
    # - in an ignored file
    repo = Repository.create(tmp_path)

    tracked_file = tmp_path / "tracked_file.tf"
    tracked_file.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(tracked_file)

    untracked_file = tmp_path / "untracked_file.tf"
    untracked_file.write_text(_IAC_SINGLE_VULNERABILITY)
    # Do NOT add this file to git
    # repo.add(untracked_file)

    ignored_file = tmp_path / "ignored_file.tf"
    ignored_file.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(ignored_file)

    repo.create_commit()

    # WHEN scanning it
    args = ["diff", "--ref", "HEAD", "--ignore-path", "ignored_file.tf", str(tmp_path)]
    result = run_ggshield_iac_scan(*args, cwd=tmp_path, expected_code=1)

    # THEN only the tracked file appears in the output
    assert "0 incidents deleted" in result.stdout
    assert "1 incident remaining" in result.stdout
    assert "0 new incidents detected" in result.stdout


@pytest.mark.parametrize("staged", (True, False))
def test_iac_scan_diff_staged(tmp_path: Path, staged: bool) -> None:
    # GIVEN a git repository
    repo = Repository.create(tmp_path)

    # AND a vulnerability in a first commit
    tracked_file = tmp_path / "first.tf"
    tracked_file.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(tracked_file)
    repo.create_commit()

    # AND a staged vulnerability
    untracked_file = tmp_path / "staged.tf"
    untracked_file.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(untracked_file)

    # WHEN scanning it with or without --staged flag
    args = ["diff", "--ref", "HEAD", str(tmp_path)]
    if staged:
        args.append("--staged")
    result = run_ggshield_iac_scan(*args, cwd=tmp_path, expected_code=1)

    # THEN the staged file only appears with --staged flag enabled
    assert "0 incidents deleted" in result.stdout
    assert "1 incident remaining" in result.stdout
    if staged:
        assert "1 new incident detected" in result.stdout
    else:
        assert "0 new incidents detected" in result.stdout
    assert ("staged.tf" in result.stdout) == staged
