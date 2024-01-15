from pathlib import Path
from typing import List, Optional

import pytest
from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.utils.os import cd
from tests.conftest import IAC_NO_VULNERABILITIES, IAC_SINGLE_VULNERABILITY
from tests.repository import Repository
from tests.unit.conftest import my_vcr


@pytest.mark.parametrize(
    "scan_arg,cassette",
    [
        (None, "test_iac_scan_prepush_output_diff"),
        ("--all", "test_iac_scan_prepush_output_all"),
    ],
)
def test_iac_scan_prepush_output(
    tmp_path: Path,
    cli_fs_runner: CliRunner,
    scan_arg: Optional[List[str]],
    cassette: str,
) -> None:
    # GIVEN a remote repository
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    # AND a local clone
    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")

    # AND a commit with a vulnerability
    sha = local_repo.create_commit()
    file = local_repo.path / "vuln.tf"
    file.write_text(IAC_SINGLE_VULNERABILITY)
    local_repo.add("vuln.tf")
    local_repo.create_commit()

    # WHEN executing the prepush command with or without the '--all' option
    with cd(str(tmp_path / "local")):
        args = ["iac", "scan", "pre-push"]
        if scan_arg is not None:
            args.append(scan_arg)

        with my_vcr.use_cassette(cassette):
            result = cli_fs_runner.invoke(
                cli,
                args,
                env={"PRE_COMMIT_FROM_REF": "", "PRE_COMMIT_TO_REF": sha},
            )
        # THEN the scan output format is correct
        if scan_arg is None:
            assert result.exit_code == 1
            assert "1 new incident detected" in result.stdout
            assert "vuln.tf" in result.stdout
            assert "1 incident detected" not in result.stdout
        else:
            assert result.exit_code == 1
            assert "1 incident detected" in result.stdout
            assert "vuln.tf" in result.stdout
            assert "1 new incident detected" not in result.stdout


@pytest.mark.parametrize("scan_arg", [None, "--all"])
@my_vcr.use_cassette("test_iac_scan_prepush_no_iac_changes_all")
def test_iac_scan_prepush_no_iac_changes(
    tmp_path: Path, cli_fs_runner: CliRunner, scan_arg: Optional[List[str]]
) -> None:
    # GIVEN a remote repository
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    # AND a local clone
    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")
    file = local_repo.path / "iac_before_hook.tf"
    file.write_text(IAC_NO_VULNERABILITIES)
    local_repo.add("iac_before_hook.tf")
    local_repo.create_commit()
    local_repo.push()

    # WHEN executing the prepush command with no IaC file in commits
    file = local_repo.path / "non_iac.txt"
    file.write_text("This should not be detected")
    local_repo.add("non_iac.txt")
    sha = local_repo.create_commit()

    with cd(str(tmp_path / "local")):
        args = ["iac", "scan", "pre-push"]
        if scan_arg is not None:
            args.append(scan_arg)

        result = cli_fs_runner.invoke(
            cli,
            args,
            env={"PRE_COMMIT_FROM_REF": "", "PRE_COMMIT_TO_REF": sha},
        )
        # THEN the scan is performed if and only if '--all' is specified
        if scan_arg is None:
            assert result.exit_code == 0
            assert "No IaC files changed" in result.stdout
            assert "iac_before_hook.tf" not in result.stdout
        else:
            assert result.exit_code == 0
            assert "No incidents have been found" in result.stdout
            assert "iac_before_hook.tf" not in result.stdout


def test_iac_scan_prepush_no_iac_files(
    tmp_path: Path, cli_fs_runner: CliRunner
) -> None:
    # GIVEN a remote repository
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    # AND a local clone
    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")
    file = local_repo.path / "before_hook.txt"
    file.write_text("This should not be detected")
    local_repo.add("before_hook.txt")
    local_repo.create_commit()
    local_repo.push()

    # WHEN executing the prepush command with --all option and no IaC file in repo
    file = local_repo.path / "non_iac.txt"
    file.write_text("This should not be detected")
    local_repo.add("non_iac.txt")
    sha = local_repo.create_commit()

    with cd(str(tmp_path / "local")):
        result = cli_fs_runner.invoke(
            cli,
            ["iac", "scan", "pre-push", "--all"],
            env={"PRE_COMMIT_FROM_REF": "", "PRE_COMMIT_TO_REF": sha},
        )
        # THEN no scan is performed
        assert result.exit_code == 0
        assert "No IaC files detected" in result.stdout
        assert "before_hook.tf" not in result.stdout
        assert "non_iac.tf" not in result.stdout
