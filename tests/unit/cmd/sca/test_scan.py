from pathlib import Path
from unittest.mock import patch

import click
from click.testing import CliRunner
from pygitguardian import GGClient

from ggshield.cmd.main import cli
from ggshield.cmd.sca.scan import (
    get_sca_scan_all_filepaths,
    sca_scan_all,
    sca_scan_diff,
)
from ggshield.core.config import Config
from ggshield.core.errors import ExitCode
from ggshield.sca.client import SCAClient
from ggshield.sca.sca_scan_models import (
    ComputeSCAFilesResult,
    SCALocationVulnerability,
    SCAScanAllOutput,
    SCAScanDiffOutput,
    SCAVulnerability,
    SCAVulnerablePackageVersion,
)
from ggshield.secret.repo import cd
from tests.repository import Repository
from tests.unit.conftest import my_vcr, write_text


def get_valid_ctx(client: GGClient) -> click.Context:
    """
    Returns a valid click.Context to run sca scan all
    """
    config = Config()
    config.verbose = False
    ctx = click.Context(
        click.Command("sca scan all"),
        obj={"client": client, "exclusion_regexes": [], "config": config},
    )
    return ctx


@my_vcr.use_cassette("test_sca_get_scan_all_filepaths.yaml", ignore_localhost=False)
def test_get_sca_scan_all_filepaths(client: GGClient, tmp_path) -> None:
    """
    GIVEN a directory and an SCAClient instance
    WHEN requesting the SCA filepaths in this directory
    THEN the API called is made without error
    THEN the existing SCA related files are listed
    """
    # Create tmp directory with some files in it
    write_text(filename=str(tmp_path / "Pipfile"), content="")
    write_text(filename=str(tmp_path / "Some_other_file.txt"), content="")
    # This one should not appear in response
    write_text(filename=str(tmp_path / ".venv" / "Pipfile"), content="")

    sca_client = SCAClient(client)

    result = get_sca_scan_all_filepaths(
        directory=tmp_path,
        exclusion_regexes=set(),
        verbose=False,
        client=sca_client,
    )

    assert result == (["Pipfile"], 200)


@my_vcr.use_cassette("test_sca_scan_all_valid.yaml", ignore_localhost=False)
def test_sca_scan_all_valid(client: GGClient) -> None:
    """
    GIVEN a valid click context
    WHEN calling sca_scan_all
    THEN we get an SCAScanAllOutput
    """

    ctx = get_valid_ctx(client)
    with ctx:
        result = sca_scan_all(ctx, Path("."))

    assert isinstance(result, SCAScanAllOutput)


@my_vcr.use_cassette("test_sca_scan_all_no_file.yaml", ignore_localhost=False)
def test_sca_scan_all_no_sca_file(client: GGClient, tmp_path: Path) -> None:
    """
    GIVEN a valid click context
    WHEN calling sca_scan_all on a directory with no sca files in it
    THEN sca_scan_all returns an empty SCAScanAllOutput instance
    """

    ctx = get_valid_ctx(client)
    with ctx:
        result = sca_scan_all(ctx, tmp_path)

    assert result == SCAScanAllOutput()


@my_vcr.use_cassette("test_sca_scan_diff.yaml", ignore_localhost=False)
def test_sca_scan_diff(client: GGClient, dummy_sca_repo: Repository):
    ctx = get_valid_ctx(client)
    with ctx:
        result = sca_scan_diff(
            ctx=ctx,
            directory=dummy_sca_repo.path,
            ref="branch_with_vuln",
            include_staged=False,
        )
    assert isinstance(result, SCAScanDiffOutput)
    assert result.scanned_files == ["Pipfile", "Pipfile.lock"]
    assert result.added_vulns == []
    assert len(result.removed_vulns) == 1


def test_sca_scan_diff_same_ref(client: GGClient, dummy_sca_repo: Repository):
    ctx = get_valid_ctx(client)
    with ctx:
        result = sca_scan_diff(
            ctx=ctx,
            directory=dummy_sca_repo.path,
            ref="HEAD",
            include_staged=False,
        )
    assert isinstance(result, SCAScanDiffOutput)
    assert result.scanned_files == []
    assert result.added_vulns == []
    assert result.removed_vulns == []


@my_vcr.use_cassette("test_sca_scan_all_no_file.yaml", ignore_localhost=False)
def test_sca_scan_all_cmd_no_sca_file(cli_fs_runner: CliRunner, tmp_path) -> None:
    """
    GIVEN a directory with no sca files in it
    WHEN running the sca scan all command
    THEN command returns the expected output
    """
    result = cli_fs_runner.invoke(
        cli,
        [
            "sca",
            "scan",
            "all",
            str(tmp_path),
        ],
    )

    assert result.exit_code == ExitCode.SUCCESS
    assert "No file to scan." in result.stdout
    assert "No SCA vulnerability has been found" in result.stdout


@my_vcr.use_cassette(ignore_localhost=False)
def test_sca_scan_all_cmd(
    cli_fs_runner: CliRunner, tmp_path, pipfile_lock_with_vuln
) -> None:
    """
    GIVEN a directory with SCA incidents
    WHEN running the sca scan all command
    THEN command returns the expected output
    """

    Path(tmp_path / "Pipfile.lock").write_text(pipfile_lock_with_vuln)

    result = cli_fs_runner.invoke(
        cli,
        [
            "sca",
            "scan",
            "all",
            str(tmp_path),
        ],
    )

    assert result.exit_code == ExitCode.SCAN_FOUND_PROBLEMS
    assert "> Pipfile.lock: 1 incident detected" in result.stdout
    assert (
        """
Severity: Medium
Summary: sqlparse contains a regular expression that is vulnerable to Regular Expression Denial of Service
A fix is available at version 0.4.4
CVE IDs: CVE-2023-30608"""
        in result.stdout
    )


@my_vcr.use_cassette("test_sca_scan_pre_commit_no_arg.yaml")
def test_sca_scan_pre_commit_no_arg(tmp_path, cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a repository
    WHEN running the sca scan pre-commit command with no argument
    THEN the return code is 0
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    with cd(str(tmp_path)):
        result = cli_fs_runner.invoke(
            cli,
            ["sca", "scan", "pre-commit"],
        )
        assert result.exit_code == ExitCode.SUCCESS
        assert "No SCA vulnerability has been added." in result.stdout


# @my_vcr.use_cassette("test_sca_scan_pre_commit_with_added_vulns.yaml")
@patch("ggshield.sca.client.SCAClient.compute_sca_files")
@patch("ggshield.sca.client.SCAClient.scan_diff")
def test_sca_scan_pre_commit_with_added_vulns(
    patch_scan_diff,
    patch_compute_sca_files,
    tmp_path,
    cli_fs_runner: CliRunner,
    pipfile_lock_with_vuln,
) -> None:
    """
    GIVEN a repository with a new file with vulns
    WHEN running the sca scan pre-commit command
    THEN we get the ExitCode.SCAN_FOUND_PROBLEMS
    THEN the text output contains the added vulnerabilities
    """

    patch_compute_sca_files.side_effect = [
        # First call, repo is empty
        ComputeSCAFilesResult(sca_files=[], potential_siblings=[]),
        # Second call, there is the dependency file
        ComputeSCAFilesResult(sca_files=["Pipfile.lock"], potential_siblings=[]),
    ]

    # TODO add ghsa_id in the patch when available
    patch_scan_diff.return_value = SCAScanDiffOutput(
        scanned_files=["Pipfile.lock"],
        added_vulns=[
            SCALocationVulnerability(
                location="Pipfile.lock",
                package_vulns=[
                    SCAVulnerablePackageVersion(
                        package_full_name="toto",
                        version="1.2.3",
                        ecosystem="pypi",
                        vulns=[
                            SCAVulnerability(
                                severity="critical",
                                summary="a vuln",
                                cve_ids=["CVE-2023"],
                            )
                        ],
                    )
                ],
            )
        ],
        removed_vulns=[
            SCALocationVulnerability(
                location="Pipfile.lock",
                package_vulns=[
                    SCAVulnerablePackageVersion(
                        package_full_name="bar",
                        version="4.5.6",
                        ecosystem="pypi",
                        vulns=[
                            SCAVulnerability(
                                severity="low",
                                summary="another vuln",
                                cve_ids=["CVE-2023-bis"],
                            )
                        ],
                    )
                ],
            )
        ],
    )

    # Create a repo
    repo = Repository.create(tmp_path)
    repo.create_commit()  # Add an initial commit, if not, ref HEAD does not exist

    # Writes a file
    file_with_vulns = Path(tmp_path / "Pipfile.lock")
    file_with_vulns.write_text("")

    # Add it to git
    repo.add(str(file_with_vulns))

    with cd(str(tmp_path)):
        result = cli_fs_runner.invoke(
            cli,
            [
                "sca",
                "scan",
                "pre-commit",
            ],
        )

        assert result.exit_code == ExitCode.SCAN_FOUND_PROBLEMS

        # Output on added vuln
        assert "> Pipfile.lock: 1 incident detected" in result.stdout
        assert (
            """
Severity: Critical
Summary: a vuln
No fix is currently available.
CVE IDs: CVE-2023"""
            in result.stdout
        )

        # Output on removed vuln
        assert "> Pipfile.lock: 1 incident removed" in result.stdout
        assert (
            """
Severity: Low
Summary: another vuln
No fix is currently available.
CVE IDs: CVE-2023-bis"""
            in result.stdout
        )
