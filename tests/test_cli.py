import os
from unittest import mock

import pytest
from click.testing import CliRunner

from ggshield.cmd import cli

from .conftest import _SIMPLE_SECRET, my_vcr


@pytest.fixture(scope="class")
def mockHookDirPath():
    with mock.patch(
        "ggshield.install.get_global_hook_dir_path", return_value="global/hooks"
    ):
        yield


@my_vcr.use_cassette()
def test_scan_file(cli_fs_runner):
    os.system('echo "This is a file with no secrets." > file')
    assert os.path.isfile("file")

    result = cli_fs_runner.invoke(cli, ["-v", "scan", "path", "file"])
    assert not result.exception
    assert "No secrets have been found" in result.output


def test_scan_file_secret(cli_fs_runner):
    os.system(f'echo "{_SIMPLE_SECRET}" > file_secret')  # nosec
    assert os.path.isfile("file_secret")

    with my_vcr.use_cassette("test_scan_file_secret"):
        result = cli_fs_runner.invoke(cli, ["-v", "scan", "path", "file_secret"])
        assert result.exit_code == 1
        assert result.exception


def test_scan_file_secret_exit_zero(cli_fs_runner):
    os.system(f'echo "{_SIMPLE_SECRET}" > file_secret')  # nosec
    assert os.path.isfile("file_secret")

    with my_vcr.use_cassette("test_scan_file_secret"):
        result = cli_fs_runner.invoke(
            cli, ["scan", "--exit-zero", "-v", "path", "file_secret"]
        )
        assert result.exit_code == 0
        assert not result.exception


class TestScanFiles:
    def create_files(self):
        os.system('echo "This is a file with no secrets." > file1')
        os.system('echo "This is a file with no secrets." > file2')

    def test_files_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["scan", "path", "file1", "file2"], input="n\n"
        )
        assert result.exit_code == 0
        assert not result.exception

    @my_vcr.use_cassette()
    def test_files_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["scan", "path", "file1", "file2", "-r", "-y"]
        )
        assert result.exit_code == 0
        assert not result.exception
        assert "" in result.output

    @my_vcr.use_cassette()
    def test_files_verbose(self, cli_fs_runner: CliRunner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli,
            ["-v", "scan", "path", "file1", "file2", "-r"],
            input="y\n",
            catch_exceptions=True,
        )
        assert result.exit_code == 0
        assert not result.exception
        assert "file1\n" in result.output
        assert "file2\n" in result.output
        assert "No secrets have been found" in result.output

    def test_files_verbose_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["-v", "scan", "path", "file1", "file2", "-r"], input="n\n"
        )
        assert result.exit_code == 0
        assert not result.exception

    @my_vcr.use_cassette()
    def test_files_verbose_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["-v", "scan", "path", "file1", "file2", "-r", "-y"]
        )
        assert result.exit_code == 0
        assert not result.exception
        assert "file1\n" in result.output
        assert "file2\n" in result.output
        assert "No secrets have been found" in result.output


class TestScanDirectory:
    def create_files(self):
        os.makedirs("dir", exist_ok=True)
        os.makedirs("dir/subdir", exist_ok=True)
        os.system('echo "This is a file with no secrets." > file1')
        os.system('echo "This is a file with no secrets." > dir/file2')
        os.system('echo "This is a file with no secrets." > dir/subdir/file3')

    def test_directory_error(self, cli_fs_runner):
        result = cli_fs_runner.invoke(cli, ["scan", "path", "-r", "./ewe-failing-test"])
        assert result.exit_code == 2
        assert result.exception
        assert "does not exist" in result.output

    def test_directory_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["scan", "path", "./", "-r"], input="n\n")
        assert result.exit_code == 0
        assert not result.exception

    @my_vcr.use_cassette()
    def test_directory_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["scan", "path", "./", "-r", "-y"])
        assert "" in result.output
        assert not result.exception

    @my_vcr.use_cassette()
    def test_directory_verbose(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["-v", "scan", "path", "./", "-r"], input="y\n"
        )
        assert not result.exception
        assert "file1\n" in result.output
        assert "dir/file2\n" in result.output
        assert "dir/subdir/file3\n" in result.output
        assert "No secrets have been found" in result.output

    def test_directory_verbose_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["-v", "scan", "path", "./", "-r"], input="n\n"
        )
        assert result.exit_code == 0
        assert not result.exception

    @my_vcr.use_cassette()
    def test_directory_verbose_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["-v", "scan", "path", "./", "-r", "-y"])
        assert not result.exception
        assert "file1\n" in result.output
        assert "dir/file2\n" in result.output
        assert "dir/subdir/file3\n" in result.output
        assert "No secrets have been found" in result.output


class TestInstallLocal:
    def test_local_exist_is_dir(self, cli_fs_runner):
        os.system("git init")
        os.makedirs(".git/hooks/pre-commit/")
        assert os.path.isdir(".git/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-m", "local"])
        os.system("rm -R .git/hooks/pre-commit")
        assert result.exit_code == 1
        assert result.exception
        assert "Error: .git/hooks/pre-commit is a directory" in result.output

    def test_local_not_exist(self, cli_fs_runner):
        assert not os.path.isfile(".git/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-m", "local"])
        assert os.path.isfile(".git/hooks/pre-commit")
        assert result.exit_code == 0
        assert "pre-commit successfully added in .git/hooks/pre-commit" in result.output

    def test_local_exist_not_force(self, cli_fs_runner):
        os.makedirs(".git/hooks", exist_ok=True)
        os.system('echo "pre-commit file" > .git/hooks/pre-commit')
        assert os.path.isfile(".git/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-m", "local"])
        assert result.exit_code == 1
        assert result.exception
        assert "Error: .git/hooks/pre-commit already exists." in result.output

    def test_local_exist_force(self, cli_fs_runner):
        os.makedirs(".git/hooks", exist_ok=True)
        os.system('echo "pre-commit file" > .git/hooks/pre-commit')
        assert os.path.isfile(".git/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-f", "-m", "local"])
        assert result.exit_code == 0
        assert "pre-commit successfully added in .git/hooks/pre-commit" in result.output


class TestInstallGlobal:
    def test_global_exist_is_dir(self, cli_fs_runner, mockHookDirPath):
        os.makedirs("global/hooks/pre-commit/")
        assert os.path.isdir("global/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-m", "global"])
        os.system("rm -R global/hooks/pre-commit")
        assert result.exit_code == 1
        assert result.exception

    def test_global_not_exist(self, cli_fs_runner, mockHookDirPath):
        assert not os.path.isfile("global/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-m", "global"])
        assert os.path.isfile("global/hooks/pre-commit")
        assert result.exit_code == 0
        assert (
            "pre-commit successfully added in global/hooks/pre-commit" in result.output
        )

    def test_global_exist_not_force(self, cli_fs_runner, mockHookDirPath):
        os.makedirs("global/hooks", exist_ok=True)
        os.system('echo "pre-commit file" > global/hooks/pre-commit')
        assert os.path.isfile("global/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-m", "global"])
        assert result.exit_code == 1
        assert result.exception
        assert "Error: global/hooks/pre-commit already exists." in result.output

    def test_global_exist_force(self, cli_fs_runner, mockHookDirPath):
        os.makedirs("global/hooks", exist_ok=True)
        os.system('echo "pre-commit file" > global/hooks/pre-commit')
        assert os.path.isfile("global/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-m", "global", "-f"])
        assert result.exit_code == 0
        assert (
            "pre-commit successfully added in global/hooks/pre-commit" in result.output
        )


class TestScanRepo:
    def test_invalid_scan_repo_github(self, cli_fs_runner):
        """
        GIVEN a repo url from github that doesn't finish in .git
        WHEN scan repo is called
        THEN a validation error proposing error correction should be shown
        """
        result = cli_fs_runner.invoke(
            cli, ["scan", "repo", "https://github.com/gitguardian/ggshield"]
        )
        assert result.exit_code == 1
        assert (
            "Error: https://github.com/gitguardian/ggshield doesn't seem to "
            "be a valid git URL.\nDid you mean "
            "https://github.com/gitguardian/ggshield.git?" in result.output
        )

    def test_invalid_scan_repo_url(self, cli_fs_runner):
        """
        GIVEN an invalid repo url from github without prefix
        WHEN scan repo is called
        THEN a validation error should be shown
        """
        result = cli_fs_runner.invoke(
            cli, ["scan", "repo", "trial.gitguardian.com/gitguardian/ggshield"]
        )
        assert result.exit_code == 1
        assert (
            "Error: trial.gitguardian.com/gitguardian/ggshield is"
            " neither a valid path nor a git URL" in result.output
        )


@pytest.mark.parametrize(
    "cassette, json_output",
    [
        ("quota", True),
        ("quota", False),
        ("quota_half_remaining", False),
        ("quota_low_remaining", False),
    ],
)
def test_quota(cassette, json_output, snapshot, cli_fs_runner):
    with my_vcr.use_cassette(cassette):
        cmd = ["quota", "--json"] if json_output else ["quota"]
        result = cli_fs_runner.invoke(cli, cmd, color=True)
        assert result.exit_code == 0
        snapshot.assert_match(result.output)


@pytest.mark.parametrize(
    "cassette, json_output",
    [
        ("test_health_check", True),
        ("test_health_check", False),
        ("test_health_check_error", False),
    ],
)
def test_api_status(cassette, json_output, snapshot, cli_fs_runner):
    with my_vcr.use_cassette(cassette):
        cmd = ["api-status", "--json"] if json_output else ["api-status"]
        result = cli_fs_runner.invoke(cli, cmd, color=True)
        assert result.exit_code == 0
        snapshot.assert_match(result.output)


@pytest.mark.parametrize("verify", [True, False])
def test_ssl_verify(cli_fs_runner, verify):
    cmd = ["api-status"] if verify else ["--allow-self-signed", "api-status"]

    with mock.patch("ggshield.utils.GGClient") as client_mock:
        cli_fs_runner.invoke(cli, cmd)
        _, kwargs = client_mock.call_args
        assert kwargs["session"].verify == verify
