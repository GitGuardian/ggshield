from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.verticals.sca.sca_scan_models import (
    ComputeSCAFilesResult,
    SCALocationVulnerability,
    SCAScanDiffOutput,
    SCAVulnerability,
    SCAVulnerablePackageVersion,
)
from ggshield.verticals.secret.repo import cd
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


@patch("ggshield.verticals.sca.client.SCAClient.compute_sca_files")
@patch("ggshield.verticals.sca.client.SCAClient.scan_diff")
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
Identifier: GHSA-abcd-1234-xxxx
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
