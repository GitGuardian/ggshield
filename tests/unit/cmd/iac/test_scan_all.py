import json
import tarfile
from io import BytesIO
from pathlib import Path
from typing import List
from unittest.mock import ANY, Mock, patch

import pytest
import requests
from click.testing import CliRunner
from pygitguardian.client import _create_tar
from pytest_mock import MockerFixture

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.utils.os import cd
from tests.conftest import IAC_SINGLE_VULNERABILITY
from tests.repository import Repository
from tests.unit.conftest import assert_invoke_exited_with, my_vcr
from tests.unit.request_mock import create_json_response


# `iac scan` is set for deprecation, but should behave exactly as `iac scan all` in the meantime
pytestmark = pytest.mark.parametrize(
    "cli_command", [["iac", "scan", "all"], ["iac", "scan"]]
)


def setup_single_iac_vuln_repo(tmp_path: Path) -> str:
    """
    Sets up a local repo with a single vulnerable IaC file from a given tmp_path.
    :returns: a string representing the path to the file
    """
    repo = Repository.create(tmp_path)

    iac_file_name = "iac_file_single_vulnerability.tf"

    tracked_file = tmp_path / iac_file_name
    tracked_file.write_text(IAC_SINGLE_VULNERABILITY)
    repo.add(tracked_file)

    repo.create_commit()
    return str(tracked_file)


@my_vcr.use_cassette("test_iac_scan_no_argument")
def test_scan_all_no_arg(cli_fs_runner: CliRunner, cli_command) -> None:
    """
    GIVEN -
    WHEN running the iac scan command with no argument
    THEN the return code is 0
    """
    result = cli_fs_runner.invoke(
        cli,
        cli_command,
    )
    assert result.exit_code == ExitCode.SUCCESS


@my_vcr.use_cassette("test_iac_scan_empty_directory")
def test_scan_all_valid_args(cli_fs_runner: CliRunner, cli_command) -> None:
    """
    GIVEN valid arguments to the iac scan command
    WHEN running the iac scan command with those arguments
    THEN the return code is 0
    """
    result = cli_fs_runner.invoke(
        cli,
        cli_command
        + [
            "--minimum-severity",
            "MEDIUM",
            "--ignore-policy",
            "GG_IAC_0001",
            "--ignore-policy",
            "GG_IAC_0002",
            "--ignore-path",
            "**",
            ".",
        ],
    )
    assert result.exit_code == ExitCode.SUCCESS


def test_invalid_policy_id(cli_fs_runner: CliRunner, cli_command) -> None:
    """
    GIVEN arguments to the iac scan command with non-correct policy id to ignore
    WHEN running the iac scan command with those arguments
    THEN the return code is 1
    """
    result = cli_fs_runner.invoke(
        cli,
        cli_command
        + [
            "--ignore-policy",
            "GG_IAC_0001",
            "--ignore-policy",
            "GG_IAC_002",
            ".",
        ],
    )
    assert result.exit_code == ExitCode.SCAN_FOUND_PROBLEMS
    assert (
        "The policies ['GG_IAC_002'] do not match the pattern 'GG_IAC_[0-9]{4}'"
        in str(result.exception)
    )


def test_iac_scan_all_file_error_response(
    cli_fs_runner: CliRunner, cli_command
) -> None:
    with cli_fs_runner.isolated_filesystem():
        iac_file_path = setup_single_iac_vuln_repo(Path("."))

        result = cli_fs_runner.invoke(
            cli,
            cli_command
            + [
                iac_file_path,
            ],
        )
    assert result.exit_code == ExitCode.USAGE_ERROR
    assert "Error: Invalid value for '[DIRECTORY]'" in result.stdout


def test_iac_scan_all_error_response(
    cli_fs_runner: CliRunner, mocker: MockerFixture, cli_command
) -> None:
    mocker.patch(
        "ggshield.core.client.GGClient.request",
        return_value=create_json_response({"detail": "Not found (404)"}, 404),
    )
    with cli_fs_runner.isolated_filesystem():
        setup_single_iac_vuln_repo(Path("."))

        result = cli_fs_runner.invoke(
            cli,
            cli_command
            + [
                ".",
            ],
        )
    assert "Error scanning." in result.stdout
    assert "The following chunk is affected" not in result.stdout
    assert "404:Not found (404)" in result.stdout


def test_iac_scan_all_json_error_response(
    cli_fs_runner: CliRunner, mocker: MockerFixture, cli_command, tmp_path: Path
) -> None:
    mocker.patch(
        "ggshield.core.client.GGClient.request",
        return_value=create_json_response({"detail": "Not found (404)"}, 404),
    )
    cli_fs_runner.mix_stderr = False
    setup_single_iac_vuln_repo(tmp_path)

    result = cli_fs_runner.invoke(
        cli,
        cli_command
        + [
            "--json",
            str(tmp_path),
        ],
    )
    assert "Error scanning." in result.stderr
    assert "404:Not found (404)" in result.stderr
    assert json.loads(result.stdout) == {
        "entities_with_incidents": [],
        "iac_engine_version": "",
        "id": str(tmp_path),
        "total_incidents": 0,
        "type": "path_scan",
    }


def test_iac_scan_all_unknown_error_response(
    cli_fs_runner: CliRunner, mocker: MockerFixture, cli_command
) -> None:
    mocker.patch(
        "ggshield.core.client.GGClient.request",
        return_value=create_json_response({"detail": "Not found (404)"}, 404),
    )

    with cli_fs_runner.isolated_filesystem():

        setup_single_iac_vuln_repo(Path("."))

        result = cli_fs_runner.invoke(
            cli,
            cli_command + ["."],
        )
    assert "Error scanning." in result.stdout
    assert "404:Not found (404)" in result.stdout


def test_iac_scan_all_error_response_read_timeout(
    cli_fs_runner: CliRunner, mocker: MockerFixture, cli_command
) -> None:
    mocker.patch(
        "ggshield.core.client.GGClient.request",
        side_effect=requests.exceptions.ReadTimeout("Timeout error"),
    )
    with cli_fs_runner.isolated_filesystem():
        setup_single_iac_vuln_repo(Path("."))

        result = cli_fs_runner.invoke(
            cli,
            cli_command + ["."],
        )
    assert "Error scanning." in result.stdout
    assert "504:The request timed out." in result.stdout


def test_iac_scan_all_verbose(cli_fs_runner: CliRunner, cli_command) -> None:
    with cli_fs_runner.isolated_filesystem():
        # GIVEN a repository with one IaC file and one non-IaC file
        path = Path(".")
        repo = Repository.create(path)

        iac_file_name = "iac_file.tf"
        non_iac_file_name = "non_iac_file.txt"

        tracked_iac_file = path / iac_file_name
        tracked_iac_file.write_text(IAC_SINGLE_VULNERABILITY)
        repo.add(tracked_iac_file)

        tracked_non_iac_file = path / non_iac_file_name
        tracked_non_iac_file.write_text(IAC_SINGLE_VULNERABILITY)
        repo.add(tracked_non_iac_file)

        repo.create_commit()

        # WHEN performing a scan all with the verbose option
        result = cli_fs_runner.invoke(
            cli,
            cli_command + [str(path), "-v"],
        )

        # THEN the IaC file appears in the output
        assert iac_file_name in result.stdout
        # AND the non-IaC file does not
        assert non_iac_file_name not in result.stdout


@patch("pygitguardian.client.GGClient.iac_directory_scan")
def test_iac_scan_all_ignored_directory(
    iac_directory_scan_mock: Mock, cli_fs_runner: CliRunner, cli_command, tmp_path: Path
) -> None:
    """
    GIVEN a directory which is ignored
    WHEN running the iac scan all command on this directory
    THEN an error is raised
    """
    repo = Repository.create(tmp_path)
    iac_file = tmp_path / "iac_file.tf"
    iac_file.write_text(IAC_SINGLE_VULNERABILITY)
    repo.add(iac_file)
    repo.create_commit()

    result = cli_fs_runner.invoke(
        cli,
        [
            "iac",
            "scan",
            "all",
            "--ignore-path",
            f"{tmp_path.name}/",
            str(tmp_path),
        ],
    )

    assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
    assert "An ignored file or directory cannot be scanned." in result.stdout
    iac_directory_scan_mock.assert_not_called()


@patch("pygitguardian.client.GGClient.iac_directory_scan")
def test_iac_scan_all_ignored_directory_config(
    iac_directory_scan_mock: Mock, cli_fs_runner: CliRunner, cli_command, tmp_path: Path
) -> None:
    """
    GIVEN a directory which is ignored in the config
    WHEN running the iac scan all command on this directory
    THEN an error is raised
    """
    repo = Repository.create(tmp_path)
    dir = tmp_path / "dir"
    dir.mkdir()
    subdir = dir / "subdir"
    subdir.mkdir()
    iac_file = subdir / "iac_file.tf"
    iac_file.write_text(IAC_SINGLE_VULNERABILITY)
    repo.add(iac_file)
    repo.create_commit()

    config = """
version: 2
iac:
    ignored_paths:
        - "dir/subdir/"

"""
    (tmp_path / ".gitguardian.yaml").write_text(config)

    with cd(str(dir)):
        result = cli_fs_runner.invoke(
            cli,
            [
                "iac",
                "scan",
                "all",
                "subdir",
            ],
        )

    assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
    assert "An ignored file or directory cannot be scanned." in result.stdout
    iac_directory_scan_mock.assert_not_called()


@patch("pygitguardian.GGClient.iac_directory_scan")
def test_iac_scan_all_context_repository(
    scan_mock: Mock, tmp_path: Path, cli_fs_runner: CliRunner, cli_command
) -> None:
    """
    GIVEN a repository with a remote url
    WHEN executing a scan all
    THEN repository url is sent
    """
    local_repo = Repository.create(tmp_path)
    remote_url = "https://github.com/owner/repository.git"
    local_repo.git("remote", "add", "origin", remote_url)

    tracked_file = local_repo.path / "iac_file_single_vulnerability.tf"
    tracked_file.write_text(IAC_SINGLE_VULNERABILITY)
    local_repo.add(tracked_file)
    local_repo.create_commit()

    cli_fs_runner.invoke(
        cli,
        cli_command
        + [
            str(local_repo.path),
        ],
    )

    scan_mock.assert_called_once_with(
        local_repo.path,
        ["iac_file_single_vulnerability.tf"],
        ANY,
        ANY,
    )
    assert any(
        isinstance(arg, dict)
        and arg.get("GGShield-Repository-URL") == "github.com/owner/repository"
        for arg in scan_mock.call_args[0]
    )


@patch("pygitguardian.client._create_tar")
def test_iac_scan_all_subdir_tar(
    create_tar_mock: Mock,
    tmp_path: Path,
    cli_fs_runner: CliRunner,
    cli_command: List[str],
) -> None:
    # GIVEN a git repository
    repo = Repository.create(tmp_path)
    repo.create_commit()

    # AND an inner directory with a vulnerability
    inner_dir_path = tmp_path / "inner" / "dir"
    inner_dir_path.mkdir(parents=True)
    (inner_dir_path / "file1.tf").write_text(IAC_SINGLE_VULNERABILITY)

    # AND another directory with a vulnerability
    other_dir_path = tmp_path / "other"
    other_dir_path.mkdir()
    (other_dir_path / "file2.tf").write_text(IAC_SINGLE_VULNERABILITY)

    repo.add(".")
    repo.create_commit()

    # WHEN scanning the inner dir
    cli_fs_runner.invoke(
        cli,
        cli_command
        + [
            str(inner_dir_path),
        ],
    )

    # THEN tar is created with the correct structure
    create_tar_mock.assert_called_once()
    path, filenames = create_tar_mock.call_args.args
    tarbytes = _create_tar(path, filenames)
    fileobj = BytesIO(tarbytes)
    with tarfile.open(fileobj=fileobj) as tar:
        assert tar.getnames() == ["inner/dir/file1.tf"]
