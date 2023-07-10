
from pathlib import Path

from tests.conftest import _IAC_SINGLE_VULNERABILITY
from tests.functional.utils import run_ggshield_iac_scan
from tests.repository import Repository

def test_iac_precommit_default(tmp_path: Path):
    # GIVEN a git repository
    repo = Repository.create(tmp_path)
    repo.create_commit()
    
    # AND stage vulnerabilities
    file = tmp_path / "precommit.tf"
    file.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(file)

    # WHEN scanning the diff between current and HEAD with pre-commit
    args = ["pre-commit", str(tmp_path)]
    result = run_ggshield_iac_scan(*args, cwd=tmp_path, expected_code=1)

    # THEN the output shows one new vulnerability
    assert "[+] 1 new incident detected (HIGH: 1)" in result.stdout

def test_iac_precommit_all(tmp_path: Path):
    # GIVEN a git repository
    repo = Repository.create(tmp_path)
    repo.create_commit()
    
    # AND stage vulnerabilities
    file = tmp_path / "precommit.tf"
    file.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(file)

    # WHEN scanning the diff between current and HEAD with pre-commit
    args = ["pre-commit", "--all", str(tmp_path)]
    result = run_ggshield_iac_scan(*args, cwd=tmp_path, expected_code=1)

    # THEN the output shows one new vulnerability
    assert "precommit.tf: 1 incident detected" in result.stdout

def test_iac_precommit_diff_not_modified(tmp_path: Path):
    # GIVEN a git repository
    repo = Repository.create(tmp_path)
    repo.create_commit()

    # WHEN scanning the diff between current and HEAD with pre-commit
    args = ["pre-commit", str(tmp_path)]
    result = run_ggshield_iac_scan(*args, cwd=tmp_path, expected_code=0)

    # THEN the output shows one new vulnerability
    assert "No IaC files changed. Skipping." in result.stdout

def test_iac_precommit_all_not_modified(tmp_path: Path):
    # GIVEN a git repository
    repo = Repository.create(tmp_path)
    repo.create_commit()
    
    # AND a first commit with vulnerabilities
    file = tmp_path / "precommit.tf"
    file.write_text(_IAC_SINGLE_VULNERABILITY)
    repo.add(file)
    repo.create_commit()

    # WHEN scanning the diff between current and HEAD with pre-commit
    args = ["pre-commit", "--all", str(tmp_path)]
    result = run_ggshield_iac_scan(*args, cwd=tmp_path, expected_code=1)

    # THEN the output shows one new vulnerability
    assert "precommit.tf: 1 incident detected" in result.stdout

def test_iac_precommit_not_iac(tmp_path: Path):
    # GIVEN a git repository
    repo = Repository.create(tmp_path)
    repo.create_commit()
    
    # WHEN scanning the diff between current and HEAD with pre-commit
    args = ["pre-commit", "--all", str(tmp_path)]
    result = run_ggshield_iac_scan(*args, cwd=tmp_path, expected_code=0)

    # THEN the output shows one new vulnerability
    assert "No incidents have been found" in result.stdout
