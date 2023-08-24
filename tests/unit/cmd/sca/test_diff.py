import pytest

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.verticals.secret.repo import cd
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
