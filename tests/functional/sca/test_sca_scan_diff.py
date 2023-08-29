import json
from pathlib import Path

from tests.functional.utils import assert_is_valid_json, run_ggshield_sca_scan
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
Identifier: GHSA-rrm6-wvj7-cwh2
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
Identifier: GHSA-rrm6-wvj7-cwh2
CVE IDs: CVE-2023-30608"""
        in proc.stdout
    )


def test_scan_diff_json_output(tmp_path: Path, pipfile_lock_with_vuln) -> None:
    """
    GIVEN a repo with a vulnerability
    WHEN scanning it with the '--json' option
    THEN the output is a valid JSON with the expected data
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    dep_file = repo.path / "Pipfile.lock"
    dep_file.write_text(pipfile_lock_with_vuln)
    repo.add("Pipfile.lock")
    repo.create_commit()

    result = run_ggshield_sca_scan(
        "diff", "--ref=HEAD~1", "--json", cwd=repo.path, expected_code=1
    )

    assert_is_valid_json(result.stdout)
    parsed_result = json.loads(result.stdout)
    assert parsed_result["scanned_files"] == ["Pipfile.lock"]
    assert len(parsed_result["added_vulns"]) == 1
    assert len(parsed_result["removed_vulns"]) == 0
    assert parsed_result["added_vulns"][0]["location"] == "Pipfile.lock"
    assert len(parsed_result["added_vulns"][0]["package_vulns"]) == 1
