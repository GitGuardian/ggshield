from pathlib import Path
from typing import List, Optional

import pytest
from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.utils.os import cd
from tests.repository import Repository
from tests.unit.conftest import my_vcr


@pytest.mark.parametrize(
    "scan_arg, cassette",
    [
        (None, "test_sca_scan_prepush_output_diff"),
        ("--all", "test_sca_scan_prepush_output_all"),
    ],
)
def test_sca_scan_prepush_output(
    tmp_path: Path,
    cli_fs_runner: CliRunner,
    scan_arg: Optional[List[str]],
    cassette: str,
    pipfile_lock_with_vuln,
) -> None:
    """
    GIVEN a remote repository and a local clone
    WHEN executing the prepush command with or without the '--all' option
    THEN the scan output format is correct
    """
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")

    sha = local_repo.create_commit()
    dep_file = local_repo.path / "Pipfile.lock"
    dep_file.write_text(pipfile_lock_with_vuln)
    local_repo.add("Pipfile.lock")
    local_repo.create_commit()

    with cd(str(tmp_path / "local")):
        args = ["sca", "scan", "pre-push"]
        if scan_arg is not None:
            args.append(scan_arg)

        with my_vcr.use_cassette(cassette):
            result = cli_fs_runner.invoke(
                cli,
                args,
                env={"PRE_COMMIT_FROM_REF": "", "PRE_COMMIT_TO_REF": sha},
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
        (None, "test_sca_scan_prepush_no_sca_changes"),
        ("--all", "test_sca_scan_prepush_no_sca_changes_all"),
    ],
)
def test_sca_scan_prepush_no_sca_changes(
    tmp_path: Path,
    cli_fs_runner: CliRunner,
    scan_arg: Optional[List[str]],
    cassette: str,
) -> None:
    """
    GIVEN a remote repository and a local clone
    WHEN executing the prepush command with no SCA file in commits
    THEN the scan is performed if and only if '--all' is specified
    """
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")
    file = local_repo.path / "Pipfile"
    file.write_text("")
    local_repo.add("Pipfile")
    local_repo.create_commit()
    local_repo.push()

    file = local_repo.path / "non_sca.txt"
    file.write_text("This should not be detected")
    local_repo.add("non_sca.txt")
    sha = local_repo.create_commit()

    with cd(str(tmp_path / "local")):
        args = ["sca", "scan", "pre-push"]
        if scan_arg is not None:
            args.append(scan_arg)

        with my_vcr.use_cassette(cassette):
            result = cli_fs_runner.invoke(
                cli,
                args,
                env={"PRE_COMMIT_FROM_REF": "", "PRE_COMMIT_TO_REF": sha},
            )
        assert result.exit_code == ExitCode.SUCCESS
        if scan_arg is None:
            assert "No SCA vulnerability has been added" in result.stdout
        else:
            assert "No SCA vulnerability has been found" in result.stdout


@my_vcr.use_cassette("test_sca_scan_prepush_no_sca_files.yaml")
def test_sca_scan_prepush_no_sca_files(
    tmp_path: Path, cli_fs_runner: CliRunner
) -> None:
    """
    GIVEN a remote repository and a local clone
    WHEN executing the prepush command with --all option and no SCA file in repo
    THEN no scan is performed
    """
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")
    file = local_repo.path / "before_hook.txt"
    file.write_text("This should not be detected")
    local_repo.add("before_hook.txt")
    local_repo.create_commit()
    local_repo.push()

    file = local_repo.path / "non_sca.txt"
    file.write_text("This should not be detected")
    local_repo.add("non_sca.txt")
    sha = local_repo.create_commit()

    with cd(str(tmp_path / "local")):
        result = cli_fs_runner.invoke(
            cli,
            ["sca", "scan", "pre-push", "--all"],
            env={"PRE_COMMIT_FROM_REF": "", "PRE_COMMIT_TO_REF": sha},
        )
        assert result.exit_code == ExitCode.SUCCESS
        assert "No file to scan." in result.stdout
        assert "No SCA vulnerability has been found" in result.stdout
