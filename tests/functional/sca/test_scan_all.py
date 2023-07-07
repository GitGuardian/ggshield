from tests.functional.utils import run_ggshield
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
    assert "Pipfile.lock" in result.stderr
    assert "sqlparse" in result.stderr


def test_sca_scan_all_without_dependency_file(dummy_sca_repo: Repository) -> None:
    """
    GIVEN a folder containing a file with vulnerabilities
    WHEN scanning it
    THEN the output says no file to scan was found
    """
    dummy_sca_repo.git("checkout", "branch_without_sca")
    result = run_ggshield(
        "sca", "scan", "all", cwd=dummy_sca_repo.path, expected_code=1
    )
    assert "No file to scan." in result.stderr
