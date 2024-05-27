from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from pygitguardian.sca_models import (
    ComputeSCAFilesResult,
    SCALocationVulnerability,
    SCAScanDiffOutput,
    SCAVulnerability,
    SCAVulnerablePackageVersion,
)

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.utils.os import cd
from tests.repository import Repository
from tests.unit.conftest import my_vcr


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


@pytest.mark.parametrize("verbose", [True, False])
@patch("pygitguardian.GGClient.compute_sca_files")
@patch("pygitguardian.GGClient.scan_diff")
def test_sca_scan_pre_commit_with_added_vulns(
    patch_scan_diff,
    patch_compute_sca_files,
    verbose,
    tmp_path,
    cli_fs_runner: CliRunner,
    pipfile_lock_with_vuln,
) -> None:
    """
    GIVEN a repository with a new file with vulns
    WHEN running the sca scan pre-commit command
    THEN we get the ExitCode.SCAN_FOUND_PROBLEMS
    THEN the text output contains the added vulnerabilities
    THEN the text output contains the removed vulnerabilities in verbose mode
    """

    patch_compute_sca_files.side_effect = [
        # First call, repo is empty
        ComputeSCAFilesResult(sca_files=[]),
        # Second call, there is the dependency file
        ComputeSCAFilesResult(sca_files=["Pipfile.lock"]),
    ]

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
                                identifier="GHSA-abcd-1234-xxxx",
                            )
                        ],
                    )
                ],
            ),
            SCALocationVulnerability(
                location="Pipfile.lock",
                package_vulns=[
                    SCAVulnerablePackageVersion(
                        package_full_name="mal_toto",
                        version="2.0.0",
                        ecosystem="pypi",
                        vulns=[
                            SCAVulnerability(
                                severity="malicious",
                                summary="a malicious vuln",
                                cve_ids=["CVE-2024"],
                                identifier="MAL-abcd-1234-xxxx",
                            )
                        ],
                    )
                ],
            ),
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
                                identifier="GHSA-efgh-5678-xxxx",
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
        cli_params = ["sca", "scan", "pre-commit"]
        if verbose:
            cli_params.append("--verbose")

        result = cli_fs_runner.invoke(cli, cli_params)

        assert result.exit_code == ExitCode.SCAN_FOUND_PROBLEMS

        # Output on added vuln
        assert "> Pipfile.lock: 2 incidents detected" in result.stdout

        assert (
            """
>>> NEW: Incident 1 (SCA): mal_toto@2.0.0
Severity: Malicious
Summary: a malicious vuln
No fix is currently available.
Identifier: MAL-abcd-1234-xxxx
CVE IDs: CVE-2024"""
            in result.stdout
        )

        assert (
            """
>>> NEW: Incident 2 (SCA): toto@1.2.3
Severity: Critical
Summary: a vuln
No fix is currently available.
Identifier: GHSA-abcd-1234-xxxx
CVE IDs: CVE-2023"""
            in result.stdout
        )

        if verbose:
            # Output on removed vuln
            assert (
                """
>>> REMOVED: Incident 3 (SCA): bar@4.5.6
Severity: Low
Identifier: GHSA-efgh-5678-xxxx
CVE IDs: CVE-2023-bis"""
                in result.stdout
            )


@my_vcr.use_cassette("test_sca_scan_pre_commit_all.yaml")
def test_pre_commit_all(dummy_sca_repo, cli_fs_runner):
    # GIVEN a repo
    dummy_sca_repo.git("checkout", "branch_with_vuln")
    dummy_sca_repo.create_commit("No files on this one")
    # With it's first commit with vulns
    # And a second one without
    # And a new file
    (dummy_sca_repo.path / "package-lock.json").touch()
    dummy_sca_repo.add()

    # WHEN scanning with `all` flag
    with cd(str(dummy_sca_repo.path)):
        result = cli_fs_runner.invoke(
            cli,
            ["sca", "scan", "pre-commit", "--all"],
        )
        # THEN we get a vulnerability
        assert result.exit_code == ExitCode.SCAN_FOUND_PROBLEMS, result
        assert "1 incident detected" in result.stdout
