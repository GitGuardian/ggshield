from pathlib import Path
from typing import List, Optional

import pytest
from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.utils.os import cd
from tests.repository import create_pre_receive_repo
from tests.unit.conftest import my_vcr


@pytest.mark.parametrize(
    "scan_arg, cassette",
    [
        (None, "test_sca_scan_prereceive_no_sca_files"),
        ("--all", "test_sca_scan_prereceive_no_sca_files_all"),
    ],
)
def test_sca_scan_prereceive_no_sca_files(
    tmp_path: Path,
    cli_fs_runner: CliRunner,
    scan_arg: Optional[List[str]],
    cassette: str,
) -> None:
    """
    GIVEN a repository without any sca files
    WHEN executing the prereceive command with or without the '--all' option
    THEN the scan output format is correct
    """
    repo = create_pre_receive_repo(tmp_path)
    old_sha = repo.get_top_sha()

    shas = [repo.create_commit() for _ in range(3)]
    with cd(repo.path):
        args = ["sca", "scan", "pre-receive"]
        if scan_arg is not None:
            args.append(scan_arg)

        with my_vcr.use_cassette(cassette):
            result = cli_fs_runner.invoke(
                cli,
                ["-v", "sca", "scan", "pre-receive"],
                input=f"{old_sha} {shas[-1]} origin/main\n",
            )
        assert result.exit_code == ExitCode.SUCCESS
        assert "No SCA vulnerability has been added" in result.stdout


@pytest.mark.parametrize(
    "scan_arg, cassette",
    [
        (None, "test_sca_scan_prereceive_with_vuln"),
        ("--all", "test_sca_scan_prereceive_with_vuln_all"),
    ],
)
def test_sca_scan_prereceive_with_vuln(
    tmp_path: Path,
    cli_fs_runner: CliRunner,
    scan_arg: Optional[List[str]],
    cassette: str,
    pipfile_lock_with_vuln,
) -> None:
    """
    GIVEN a repository with a commit with an SCA vulnerability
    WHEN executing the prereceive command with or without the '--all' option
    THEN the vulnerability is detected
    """
    repo = create_pre_receive_repo(tmp_path)
    old_sha = repo.get_top_sha()

    dep_file = repo.path / "Pipfile.lock"
    dep_file.write_text(pipfile_lock_with_vuln)
    repo.add("Pipfile.lock")
    sha = repo.create_commit()
    with cd(repo.path):
        args = ["sca", "scan", "pre-receive"]
        if scan_arg is not None:
            args.append(scan_arg)

        with my_vcr.use_cassette(cassette):
            result = cli_fs_runner.invoke(
                cli,
                ["-v", "sca", "scan", "pre-receive"],
                input=f"{old_sha} {sha} origin/main\n",
            )
        assert result.exit_code == ExitCode.SCAN_FOUND_PROBLEMS
        assert "> Pipfile.lock: 1 incident detected" in result.stdout
        assert (
            """
Severity: High
Summary: sqlparse parsing heavily nested list leads to Denial of Service
A fix is available at version 0.5.0
Identifier: GHSA-2m57-hf25-phgg
CVE IDs: CVE-2024-4340"""
            in result.stdout
        )


@pytest.mark.parametrize(
    "scan_arg, cassette",
    [
        (None, "test_sca_scan_prereceive_no_sca_changes"),
        ("--all", "test_sca_scan_prereceive_no_sca_changes_all"),
    ],
)
def test_sca_scan_prereceive_no_sca_changes(
    tmp_path: Path,
    cli_fs_runner: CliRunner,
    scan_arg: Optional[List[str]],
    cassette: str,
) -> None:
    """
    GIVEN a repository with a dependecy files without vulnerabilities
    WHEN executing the prereceive command with no SCA file in commits
    THEN the output format is correct
    """
    repo = create_pre_receive_repo(tmp_path)
    old_sha = repo.get_top_sha()

    file = repo.path / "Pipfile"
    file.write_text("")
    repo.add("Pipfile")
    sha = repo.create_commit()

    with cd(repo.path):
        args = ["sca", "scan", "pre-receive"]
        if scan_arg is not None:
            args.append(scan_arg)

        with my_vcr.use_cassette(cassette):
            result = cli_fs_runner.invoke(
                cli,
                ["-v", "sca", "scan", "pre-receive"],
                input=f"{old_sha} {sha} origin/main\n",
            )
        assert result.exit_code == ExitCode.SUCCESS
        assert "No SCA vulnerability has been added" in result.stdout
