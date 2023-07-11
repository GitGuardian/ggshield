import os
from pathlib import Path
from typing import List, Optional

import pytest

from tests.conftest import _IAC_SINGLE_VULNERABILITY
from tests.functional.utils import run_ggshield_iac_scan
from tests.repository import Repository


def test_ci_diff_no_vuln(tmp_path: Path) -> None:
    # GIVEN a repository
    repository = Repository.create(tmp_path)
    # AND a file with no vulnerability
    no_iac_file = tmp_path / "no_iac_file.tf"
    no_iac_file.write_text("Nothing to see here")
    # AND a file with a vulnerability
    iac_file = tmp_path / "iac_file.tf"
    iac_file.write_text(_IAC_SINGLE_VULNERABILITY)
    # AND an initial commit
    repository.add(iac_file)
    repository.create_commit()
    # WHEN scanning it
    result = run_ggshield_iac_scan(*["ci"], cwd=tmp_path, expected_code=0)
    # THEN no vulnerability should be found
    assert "> No IaC files changed. Skipping." in result.stdout

def test_ci_diff_vuln(tmp_path: Path) -> None:
    # GIVEN a repository
    repository = Repository.create(tmp_path)
    # AND a file without a vulnerability
    no_iac_file = tmp_path / "no_iac_file.tf"
    no_iac_file.write_text("Nothing to see here")
    # AND an initial commit
    repository.add(no_iac_file)
    repository.create_commit()
    # AND a staged file with a vulnerability
    iac_file = tmp_path / "iac_file.tf"
    iac_file.write_text(_IAC_SINGLE_VULNERABILITY)
    repository.add(iac_file)
    # WHEN scanning it
    result = run_ggshield_iac_scan(*["ci"], cwd=tmp_path, expected_code=1)
    # THEN a new vulnerability should be found
    assert "[+] 1 new incident detected (HIGH: 1)" in result.stdout

def test_ci_all_no_vuln(tmp_path: Path) -> None:
    # GIVEN a repository
    repository = Repository.create(tmp_path)
    # AND a file without a vulnerability
    no_iac_file = tmp_path / "no_iac_file.tf"
    no_iac_file.write_text("Nothing to see here")
    # AND an initial commit
    repository.add(no_iac_file)
    repository.create_commit()
    # WHEN scanning it
    result = run_ggshield_iac_scan(*["ci", "--all"], cwd=tmp_path, expected_code=0)
    # THEN no vulnerability should be found
    assert "No incidents have been found" in result.stdout

def test_ci_all_vuln(tmp_path: Path) -> None:
    # GIVEN a repository
    repository = Repository.create(tmp_path)
    # AND a file with a vulnerability
    iac_file = tmp_path / "iac_file.tf"
    iac_file.write_text(_IAC_SINGLE_VULNERABILITY)
    # AND an initial commit
    repository.add(iac_file)
    repository.create_commit()
    # WHEN scanning it
    result = run_ggshield_iac_scan(*["ci", "--all"], cwd=tmp_path, expected_code=1)
    # THEN a new vulnerability should be found
    assert "iac_file.tf: 1 incident detected" in result.stdout