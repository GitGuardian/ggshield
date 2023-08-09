from pathlib import Path

from tests.functional.utils import run_ggshield_sca_scan
from tests.repository import Repository


def test_scan_ci_diff(tmp_path: Path, monkeypatch, pipfile_lock_with_vuln) -> None:
    """
    GIVEN a repository with a commit containing a vuln,
    two clean commits on top of it, and a CI env
    WHEN scanning the last two commits, it's OK
    WHEN scanning the last three commits, including the vuln
    THEN the vuln is found
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    dep_file = repo.path / "Pipfile.lock"
    dep_file.write_text(pipfile_lock_with_vuln)
    repo.add("Pipfile.lock")

    for _ in range(3):
        repo.create_commit()

    env = {"CI": "true", "GITLAB_CI": "true"}
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    monkeypatch.setenv("CI_COMMIT_BEFORE_SHA", "HEAD~2")
    run_ggshield_sca_scan("ci", expected_code=0, cwd=repo.path)

    monkeypatch.setenv("CI_COMMIT_BEFORE_SHA", "HEAD~3")
    proc = run_ggshield_sca_scan("ci", expected_code=1, cwd=repo.path)
    assert "> Pipfile.lock: 1 incident detected" in proc.stdout
    assert (
        """
Severity: Medium
Summary: sqlparse contains a regular expression that is vulnerable to Regular Expression Denial of Service
A fix is available at version 0.4.4
Identifier: GHSA-rrm6-wvj7-cwh2
CVE IDs: CVE-2023-30608"""
        in proc.stdout
    )


def test_scan_ci_all_no_files(tmp_path, monkeypatch) -> None:
    """
    GIVEN an empty repository, and a CI env
    WHEN scanning with the "--all" flag
    THEN the command returns the expected output
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    env = {"CI": "true", "GITLAB_CI": "true"}
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    proc = run_ggshield_sca_scan("ci", "--all", expected_code=0, cwd=repo.path)
    assert "No SCA vulnerability has been found" in proc.stdout


def test_scan_ci_all(tmp_path, monkeypatch, pipfile_lock_with_vuln) -> None:
    """
    GIVEN a file containing a vuln, and a CI env
    WHEN scanning with the "--all" flag
    THEN the vuln is found
    """
    sca_file = tmp_path / "Pipfile.lock"
    sca_file.write_text(pipfile_lock_with_vuln)

    env = {"CI": "true", "GITLAB_CI": "true"}
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    proc = run_ggshield_sca_scan("ci", "--all", expected_code=1, cwd=tmp_path)
    assert "> Pipfile.lock: 1 incident detected" in proc.stdout
    assert (
        """
Severity: Medium
Summary: sqlparse contains a regular expression that is vulnerable to Regular Expression Denial of Service
A fix is available at version 0.4.4
Identifier: GHSA-rrm6-wvj7-cwh2
CVE IDs: CVE-2023-30608"""
        in proc.stdout
    )
