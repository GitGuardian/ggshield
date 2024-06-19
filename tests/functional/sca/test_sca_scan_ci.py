import re
from pathlib import Path

from tests.functional.utils import run_ggshield_sca_scan
from tests.repository import Repository


def test_scan_ci(tmp_path: Path, pipfile_lock_with_vuln) -> None:
    """
    GIVEN a repository with a commit containing a vuln,
    two clean commits on top of it, and a CI env
    WHEN scanning the last two commits, it's OK
    WHEN scanning the last three commits, including the vuln
    THEN the vuln is found
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    repo.create_branch("mr_branch")
    dep_file = repo.path / "Pipfile.lock"
    dep_file.write_text(pipfile_lock_with_vuln)
    repo.add("Pipfile.lock")
    repo.create_commit()

    env = {
        "GITLAB_CI": "1",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
        "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "mr_branch",
    }
    proc = run_ggshield_sca_scan("ci", expected_code=1, cwd=repo.path, env=env)
    assert bool(re.search(r"> Pipfile\.lock: \d+ incidents? detected", proc.stdout))
    assert (
        """
Severity: High
Summary: sqlparse parsing heavily nested list leads to Denial of Service
A fix is available at version 0.5.0
Identifier: GHSA-2m57-hf25-phgg
CVE IDs: CVE-2024-4340"""
        in proc.stdout
    )


def test_scan_ci_no_commit(tmp_path) -> None:
    """
    GIVEN a repository, with a branch containing no new commit
    WHEN scanning it with scan ci
    THEN the scan is skipped
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()
    repo.create_branch("mr_branch")

    env = {
        "GITLAB_CI": "1",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
        "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "mr_branch",
    }
    proc = run_ggshield_sca_scan("ci", expected_code=0, cwd=repo.path, env=env)
    assert "No commit found in merge request, skipping scan." in proc.stderr
