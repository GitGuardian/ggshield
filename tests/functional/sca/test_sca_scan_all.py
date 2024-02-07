import json
from typing import Any, Dict

import jsonschema

from tests.functional.utils import assert_is_valid_json, run_ggshield
from tests.repository import Repository


def test_sca_scan_all_with_vuln(dummy_sca_repo: Repository) -> None:
    """
    GIVEN a folder containing a file with vulnerabilities
    WHEN scanning it
    THEN the name of the lock file is in the output
    THEN the name of the vulnerable dependency is in the output
    """
    dummy_sca_repo.git("checkout", "branch_with_vuln")
    result = run_ggshield(
        "sca", "scan", "all", cwd=dummy_sca_repo.path, expected_code=1
    )
    assert "Pipfile.lock" in result.stdout
    assert "sqlparse" in result.stdout


def test_sca_scan_all_without_dependency_file(dummy_sca_repo: Repository) -> None:
    """
    GIVEN a folder containing a file with vulnerabilities
    WHEN scanning it
    THEN the output contains "No file to scan"
    """
    dummy_sca_repo.git("checkout", "branch_without_sca")
    result = run_ggshield(
        "sca", "scan", "all", cwd=dummy_sca_repo.path, expected_code=0
    )
    assert "No file to scan." in result.stderr


def test_scan_all_json_output(
    dummy_sca_repo: Repository, sca_scan_all_json_schema: Dict[str, Any]
) -> None:
    """
    GIVEN a repo with a vulnerability
    WHEN scanning it with the '--json' option
    THEN the output is a valid JSON with the expected data
    """
    dummy_sca_repo.git("checkout", "branch_with_vuln")

    result = run_ggshield(
        "sca", "scan", "all", "--json", cwd=dummy_sca_repo.path, expected_code=1
    )

    assert_is_valid_json(result.stdout)
    parsed_result = json.loads(result.stdout)
    assert len(parsed_result["scanned_files"]) == 2
    assert len(parsed_result["found_package_vulns"]) == 1
    assert parsed_result["found_package_vulns"][0]["location"] == "Pipfile.lock"
    assert len(parsed_result["found_package_vulns"][0]["package_vulns"]) == 1
    jsonschema.validate(parsed_result, sca_scan_all_json_schema)
