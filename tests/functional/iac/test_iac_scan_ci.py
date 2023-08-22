from pathlib import Path
from typing import Optional

import pytest

from tests.conftest import _IAC_SINGLE_VULNERABILITY
from tests.functional.utils import run_ggshield_iac_scan
from tests.repository import Repository


@pytest.mark.parametrize(
    "scan_arg,file_content,expected_code,expected_output",
    [
        (None, "Nothing to see here", 0, "No new incident"),
        (None, _IAC_SINGLE_VULNERABILITY, 1, "[+] 1 new incident detected (HIGH: 1)"),
        ("--all", "Nothing to see here", 0, "No incidents have been found"),
        ("--all", _IAC_SINGLE_VULNERABILITY, 1, "1 incident detected"),
    ],
)
def test_ci_diff_no_vuln(
    tmp_path: Path,
    scan_arg: Optional[str],
    file_content: str,
    expected_code: int,
    expected_output: str,
) -> None:
    # GIVEN a repository
    repository = Repository.create(tmp_path)
    initial_sha = repository.create_commit()

    # AND a commit containing a file with or without a vulnerability
    test_file = tmp_path / "test_file.tf"
    test_file.write_text(file_content)
    repository.add(test_file)
    repository.create_commit()

    # AND an unstaged file with a vulnerability
    iac_file = tmp_path / "iac_file.tf"
    iac_file.write_text(_IAC_SINGLE_VULNERABILITY)

    # WHEN scanning it
    args = ["ci"]
    if scan_arg is not None:
        args.append(scan_arg)
    result = run_ggshield_iac_scan(
        *args,
        cwd=tmp_path,
        expected_code=expected_code,
        env={"GITLAB_CI": "1", "CI_COMMIT_BEFORE_SHA": initial_sha},
    )

    # THEN a vulnerability should be found if and only if
    # the committed file contains one
    assert "iac_file.tf" not in result.stdout
    assert ("test_file.tf" in result.stdout) == (
        file_content == _IAC_SINGLE_VULNERABILITY
    )
    assert expected_output in result.stdout
