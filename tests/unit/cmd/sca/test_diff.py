from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.utils.os import cd
from tests.repository import Repository
from tests.unit.conftest import my_vcr


@pytest.mark.parametrize(
    ("nb_commits_history", "exit_code", "output_message", "cassette"),
    (
        (
            1,
            ExitCode.SUCCESS,
            "No SCA vulnerability has been added",
            "test_sca_scan_diff_no_vuln.yaml",
        ),
        (
            2,
            ExitCode.SCAN_FOUND_PROBLEMS,
            "1 incident detected",
            "test_sca_scan_diff_vuln.yaml",
        ),
    ),
)
def test_scan_diff(
    dummy_sca_repo,
    cli_fs_runner,
    nb_commits_history,
    exit_code,
    output_message,
    cassette,
):
    # GIVEN a repo
    # With it's first commit with vulns
    dummy_sca_repo.git("checkout", "branch_with_vuln")
    # And a second and third one without
    dummy_sca_repo.create_commit("No files on this one")
    # And a new file
    (dummy_sca_repo.path / "package-lock.json").touch()
    dummy_sca_repo.add()

    # WHEN scanning
    with cd(str(dummy_sca_repo.path)):
        with my_vcr.use_cassette(cassette):
            result = cli_fs_runner.invoke(
                cli,
                ["sca", "scan", "diff", f"--ref=HEAD~{nb_commits_history}"],
            )
            # THEN we get a vulnerability when a commit contains any
            assert result.exit_code == exit_code, result
            assert output_message in result.stdout


@patch("pygitguardian.GGClient.scan_diff")
@my_vcr.use_cassette("test_sca_scan_diff_context_repository.yaml")
def test_sca_scan_diff_context_repository(
    scan_mock: Mock, tmp_path: Path, cli_fs_runner: CliRunner, pipfile_lock_with_vuln
) -> None:
    """
    GIVEN a repository with a remote url
    WHEN executing a scan diff
    THEN repository url is sent
    """
    local_repo = Repository.create(tmp_path)
    remote_url = "https://github.com/owner/repository.git"
    local_repo.git("remote", "add", "origin", remote_url)
    local_repo.create_commit()

    file = local_repo.path / "Pipfile.lock"
    file.write_text(pipfile_lock_with_vuln)
    local_repo.add(file)

    cli_fs_runner.invoke(
        cli,
        [
            "sca",
            "scan",
            "diff",
            "--ref",
            "HEAD",
            "--staged",
            str(local_repo.path),
        ],
    )

    scan_mock.assert_called_once()
    assert (
        scan_mock.call_args[1].get("extra_headers").get("GGShield-Repository-URL")
        == "github.com/owner/repository"
    )
