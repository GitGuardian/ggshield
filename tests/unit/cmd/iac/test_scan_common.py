from pathlib import Path
from typing import List

import pytest
from click.testing import CliRunner

from ggshield.__main__ import cli
from tests.conftest import IAC_SINGLE_VULNERABILITY
from tests.repository import Repository
from tests.unit.conftest import my_vcr


_SCAN_COMMAND = ["scan"]
_SCAN_ALL_COMMAND = ["scan", "all"]
_SCAN_DIFF_COMMAND = ["scan", "diff", "--ref", "HEAD~1"]


@pytest.mark.parametrize("exit_zero", [True, False])
@pytest.mark.parametrize(
    "command,cassette",
    [
        (_SCAN_COMMAND, "test_iac_scan_exit_zero"),
        (_SCAN_ALL_COMMAND, "test_iac_scan_all_exit_zero"),
        (_SCAN_DIFF_COMMAND, "test_iac_scan_diff_exit_zero"),
    ],
)
def test_iac_scan_exit_zero(
    cli_fs_runner: CliRunner,
    tmp_path: Path,
    exit_zero: bool,
    command: List[str],
    cassette: str,
) -> None:
    """
    GIVEN a directory with vulnerabilities
    WHEN running the iac scan command with --exit-zero
    THEN the return code is 0
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()
    first_file = repo.path / "file.tf"
    first_content = IAC_SINGLE_VULNERABILITY
    first_file.write_text(first_content)
    repo.add("file.tf")
    repo.create_commit()

    args = ["iac"] + command + [str(tmp_path)]
    if exit_zero:
        args.append("--exit-zero")

    with my_vcr.use_cassette(cassette):
        result = cli_fs_runner.invoke(cli, args)

    assert result.exit_code == (not exit_zero)
