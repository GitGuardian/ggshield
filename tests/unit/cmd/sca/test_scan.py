import re
from pathlib import Path
from unittest.mock import patch

import click
from click.testing import CliRunner
from pygitguardian import GGClient

from ggshield.__main__ import cli
from ggshield.cmd.sca.scan.sca_scan_utils import (
    get_sca_scan_all_filepaths,
    sca_scan_all,
    sca_scan_diff,
)
from ggshield.core.config import Config
from ggshield.core.errors import ExitCode
from ggshield.core.scan.scan_mode import ScanMode
from ggshield.utils.os import cd
from ggshield.verticals.sca.client import SCAClient
from ggshield.verticals.sca.sca_scan_models import (
    SCALocationVulnerability,
    SCAScanAllOutput,
    SCAScanDiffOutput,
    SCAVulnerability,
    SCAVulnerablePackageVersion,
)
from tests.repository import Repository
from tests.unit.conftest import my_vcr, write_text


def get_valid_ctx(client: GGClient) -> click.Context:
    """
    Returns a valid click.Context to run sca scan all
    """
    config = Config()
    config.user_config.verbose = False
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


def test_sca_scan_all_ignore_path(client: GGClient, dummy_sca_repo: Repository) -> None:
    """
    GIVEN a directory with sca files that are ignored
    WHEN scanning
    THEN no files are scanned
    """
    dummy_sca_repo.git("checkout", "branch_with_vuln")
    ctx = get_valid_ctx(client)
    ctx.obj["exclusion_regexes"] = {
        re.compile(r"Pipfile"),
        re.compile(r"Pipfile.lock"),
        re.compile(r"dummy_file.py"),
    }
    with ctx:
        result = sca_scan_all(ctx, dummy_sca_repo.path)

    assert result == SCAScanAllOutput()


@my_vcr.use_cassette("test_sca_scan_diff.yaml", ignore_localhost=False)
def test_sca_scan_diff(client: GGClient, dummy_sca_repo: Repository):
    ctx = get_valid_ctx(client)
    with ctx:
        result = sca_scan_diff(
            ctx=ctx,
            directory=dummy_sca_repo.path,
            previous_ref="branch_with_vuln",
            scan_mode=ScanMode.DIFF,
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
            previous_ref="HEAD",
            scan_mode=ScanMode.DIFF,
        )
    assert isinstance(result, SCAScanDiffOutput)
    assert result.scanned_files == []
    assert result.added_vulns == []
    assert result.removed_vulns == []


@my_vcr.use_cassette("test_sca_scan_diff_ignore.yaml", ignore_localhost=False)
def test_sca_scan_diff_ignore_path(
    client: GGClient, dummy_sca_repo: Repository
) -> None:
    """
    GIVEN a directory with sca files that are ignored
    WHEN scanning
    THEN no files are scanned
    """
    dummy_sca_repo.git("checkout", "branch_without_vuln")
    ctx = get_valid_ctx(client)
    ctx.obj["exclusion_regexes"] = {
        re.compile(r"Pipfile"),
        re.compile(r"Pipfile.lock"),
    }
    with ctx:
        result = sca_scan_diff(
            ctx=ctx,
            directory=dummy_sca_repo.path,
            previous_ref="branch_with_vuln",
            scan_mode=ScanMode.DIFF,
        )

    assert result == SCAScanDiffOutput()


@patch("ggshield.verticals.sca.client.SCAClient.scan_diff")
def test_sca_scan_diff_no_files(
    scan_diff_mock, client: GGClient, dummy_sca_repo: Repository
) -> None:
    """
    GIVEN a repo
    WHEN scanning the diff with all files ignored
    THEN no scan is triggered
    """
    ctx = get_valid_ctx(client)
    ctx.obj["exclusion_regexes"] = {re.compile(".*")}
    with ctx:
        sca_scan_diff(
            ctx=ctx,
            directory=dummy_sca_repo.path,
            previous_ref="HEAD",
            include_staged=True,
            scan_mode=ScanMode.DIFF,
        )

    scan_diff_mock.assert_not_called()


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
Identifier: GHSA-rrm6-wvj7-cwh2
CVE IDs: CVE-2023-30608"""
        in result.stdout
    )


@my_vcr.use_cassette("test_sca_scan_all_exit_zero.yaml")
def test_sca_scan_all_exit_zero(
    tmp_path, cli_fs_runner, pipfile_lock_with_vuln
) -> None:
    file_with_vulns = Path(tmp_path / "Pipfile.lock")
    file_with_vulns.write_text(pipfile_lock_with_vuln)

    with cd(str(tmp_path)):
        result = cli_fs_runner.invoke(
            cli,
            [
                "sca",
                "scan",
                "all",
                "--exit-zero",
            ],
        )

        assert result.exit_code == ExitCode.SUCCESS


@patch("ggshield.cmd.sca.scan.all.sca_scan_all")
def test_sca_text_handler_ordering(patch_scan_all, cli_fs_runner):
    """
    GIVEN an unordered result for a SCA scan all
    WHEN printing the result
    THEN vulnerabilities are ordered as expected
    """
    patch_scan_all.return_value = SCAScanAllOutput(
        scanned_files=["Pipfile.lock", "toto/Pipfile.lock"],
        found_package_vulns=[
            SCALocationVulnerability(
                location="Pipfile.lock",
                package_vulns=[
                    SCAVulnerablePackageVersion(
                        package_full_name="toto",
                        version="1.0.0",
                        ecosystem="pypi",
                        vulns=[
                            SCAVulnerability(severity="low", summary="", identifier="")
                        ],
                    ),
                    SCAVulnerablePackageVersion(
                        package_full_name="titi",
                        version="2.0.0",
                        ecosystem="pypi",
                        vulns=[
                            SCAVulnerability(
                                severity="medium", summary="", identifier=""
                            )
                        ],
                    ),
                ],
            ),
            SCALocationVulnerability(
                location="toto/Pipfile.lock",
                package_vulns=[
                    SCAVulnerablePackageVersion(
                        package_full_name="foo",
                        version="1.0.5",
                        ecosystem="pypi",
                        vulns=[
                            SCAVulnerability(severity="high", summary="", identifier="")
                        ],
                    ),
                    SCAVulnerablePackageVersion(
                        package_full_name="bar",
                        version="2.5.6",
                        ecosystem="pypi",
                        vulns=[
                            SCAVulnerability(
                                severity="critical", summary="", identifier=""
                            )
                        ],
                    ),
                ],
            ),
        ],
    )

    result = cli_fs_runner.invoke(
        cli,
        [
            "sca",
            "scan",
            "all",
        ],
    )

    assert result.exit_code == ExitCode.SCAN_FOUND_PROBLEMS
    assert (
        """> toto/Pipfile.lock: 2 incidents detected

>>> : Incident 1 (SCA): bar@2.5.6
Severity: Critical
Summary: 
No fix is currently available.
Identifier: 
CVE IDs: -

>>> : Incident 2 (SCA): foo@1.0.5
Severity: High
Summary: 
No fix is currently available.
Identifier: 
CVE IDs: -

> Pipfile.lock: 2 incidents detected

>>> : Incident 1 (SCA): titi@2.0.0
Severity: Medium
Summary: 
No fix is currently available.
Identifier: 
CVE IDs: -

>>> : Incident 2 (SCA): toto@1.0.0
Severity: Low
Summary: 
No fix is currently available.
Identifier: 
CVE IDs: -"""  # noqa W291
        in result.stdout
    )
