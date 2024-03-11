from pathlib import Path
from unittest.mock import Mock, patch

from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.utils.os import cd
from tests.conftest import IAC_SINGLE_VULNERABILITY
from tests.repository import Repository
from tests.unit.conftest import assert_invoke_exited_with, my_vcr


@my_vcr.use_cassette("test_iac_scan_diff_no_argument")
def test_scan_diff_no_arg(tmp_path, cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a repository
    WHEN running the iac scan diff command with no argument
    THEN the return code is 0
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    with cd(str(tmp_path)):
        result = cli_fs_runner.invoke(
            cli,
            ["iac", "scan", "diff", "--ref", "HEAD"],
        )
        assert result.exit_code == ExitCode.SUCCESS


@my_vcr.use_cassette("test_iac_scan_diff_valid_args")
def test_scan_diff_valid_args(tmp_path, cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a repository and valid arguments to the iac scan diff command
    WHEN running the iac scan diff command with those arguments
    THEN the return code is 0
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "diff",
            "--ref",
            "HEAD",
            "--staged",
            "--minimum-severity",
            "MEDIUM",
            "--ignore-policy",
            "GG_IAC_0001",
            "--ignore-policy",
            "GG_IAC_0002",
            "--ignore-path",
            str(tmp_path / "directory"),
            str(tmp_path),
        ],
    )
    assert result.exit_code == ExitCode.SUCCESS


def test_invalid_policy_id(tmp_path, cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a repository and arguments to the iac scan diff command with non-correct policy id to ignore
    WHEN running the iac scan diff command with those arguments
    THEN the return code is 1
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "diff",
            "--ref",
            "HEAD",
            "--ignore-policy",
            "GG_IAC_0001",
            "--ignore-policy",
            "GG_IAC_002",
            str(tmp_path),
        ],
    )
    assert result.exit_code == ExitCode.SCAN_FOUND_PROBLEMS
    assert (
        "The policies ['GG_IAC_002'] do not match the pattern 'GG_IAC_[0-9]{4}'"
        in str(result.exception)
    )


def test_iac_scan_diff_file_error_response(tmp_path, cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a file
    WHEN running the iac scan diff command with a single file as path parameter
    THEN an error is thrown
    """
    file_path = Path(tmp_path / "iac_file_single_vulnerability.tf")
    file_path.write_text(IAC_SINGLE_VULNERABILITY)

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "diff",
            "--ref",
            "HEAD",
            str(file_path),
        ],
    )
    assert result.exit_code == ExitCode.USAGE_ERROR
    assert "Error: Invalid value for '[DIRECTORY]'" in result.stdout


def test_iac_scan_diff_no_ref_arg(tmp_path, cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a repository
    WHEN running the iac scan diff command with no ref argument
    THEN the return code is 2
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    with cd(str(tmp_path)):
        result = cli_fs_runner.invoke(
            cli,
            [
                "iac",
                "scan",
                "diff",
            ],
        )
        assert result.exit_code == ExitCode.USAGE_ERROR
        assert "Error: Missing option '--ref'" in result.stdout


def test_iac_scan_diff_invalid_reference(tmp_path, cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a repository
    WHEN running the iac scan diff command with an invalid git reference
    THEN the return code is 1
    """
    repo = Repository.create(tmp_path)
    repo.create_commit()

    with cd(str(tmp_path)):
        result1 = cli_fs_runner.invoke(
            cli,
            ["iac", "scan", "diff", "--ref", "invalid_ref"],
        )
        assert result1.exit_code == ExitCode.USAGE_ERROR
        assert "Not a git reference" in result1.stdout


@patch("pygitguardian.client.GGClient.iac_diff_scan")
def test_iac_scan_diff_ignored_directory(
    iac_diff_scan_mock: Mock, cli_fs_runner: CliRunner
) -> None:
    """
    GIVEN a directory which is ignored
    WHEN running the iac scan diff command on this directory
    THEN an error is raised
    """
    path = Path(".")
    repo = Repository.create(path)
    initial_commit = repo.create_commit()
    iac_file = path / "iac_file.tf"
    iac_file.write_text(IAC_SINGLE_VULNERABILITY)
    repo.add(iac_file)
    repo.create_commit()

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "diff",
            "--ref",
            initial_commit,
            "--ignore-path",
            f"{path.name}/",
            str(path),
        ],
    )

    assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
    assert "An ignored file or directory cannot be scanned." in result.stdout
    iac_diff_scan_mock.assert_not_called()


@patch("pygitguardian.GGClient.iac_diff_scan")
def test_iac_scan_diff_context_repository(
    scan_mock: Mock,
    tmp_path: Path,
    cli_fs_runner: CliRunner,
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

    tracked_file = local_repo.path / "iac_file_single_vulnerability.tf"
    tracked_file.write_text(IAC_SINGLE_VULNERABILITY)
    local_repo.add(tracked_file)

    cli_fs_runner.invoke(
        cli,
        ["iac", "scan", "diff", "--ref", "HEAD", "--staged", str(local_repo.path)],
    )

    scan_mock.assert_called_once()
    assert any(
        isinstance(arg, dict)
        and arg.get("GGShield-Repository-URL") == "github.com/owner/repository"
        for arg in scan_mock.call_args[0]
    )
