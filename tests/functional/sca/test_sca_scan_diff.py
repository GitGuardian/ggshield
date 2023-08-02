from pathlib import Path

from tests.functional.utils import run_ggshield_sca_scan
from tests.repository import Repository


def test_scan_diff(tmp_path: Path, pipfile_lock_with_vuln) -> None:
    """
    GIVEN a repository with a commit containing a vuln,
    one clean commits on top of it
    WHEN scanning the HEAD before the commit containing the vulns
    WHEN scanning the last two commits, it's OK
    WHEN scanning the commit containing the vuln
    THEN the vuln is found
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    dep_file = repo.path / "Pipfile.lock"
    dep_file.write_text(pipfile_lock_with_vuln)
    repo.add("Pipfile.lock")

    proc = run_ggshield_sca_scan(
        "diff", "--ref=HEAD", "--staged", expected_code=1, cwd=repo.path
    )
    assert "> Pipfile.lock: 1 incident detected" in proc.stdout
    assert (
        """
Severity: Medium
Summary: sqlparse contains a regular expression that is vulnerable to Regular Expression Denial of Service
A fix is available at version 0.4.4
CVE IDs: CVE-2023-30608"""
        in proc.stdout
    )

    for _ in range(2):
        repo.create_commit()

    run_ggshield_sca_scan("diff", "--ref=HEAD~1", expected_code=0, cwd=repo.path)

    proc = run_ggshield_sca_scan("diff", "--ref=HEAD~2", expected_code=1, cwd=repo.path)
    assert "> Pipfile.lock: 1 incident detected" in proc.stdout
    assert (
        """
Severity: Medium
Summary: sqlparse contains a regular expression that is vulnerable to Regular Expression Denial of Service
A fix is available at version 0.4.4
CVE IDs: CVE-2023-30608"""
        in proc.stdout
    )
