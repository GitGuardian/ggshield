import os
import pytest
from unittest import mock

from click.testing import CliRunner
from secrets_shield.secrets_shield import cli


@pytest.fixture(scope="session")
def cli_runner():
    return CliRunner()


@pytest.fixture(scope="session")
def cli_fs_runner(cli_runner):
    with cli_runner.isolated_filesystem():
        yield cli_runner


@pytest.fixture(scope="class")
def mockHookDirPath():
    with mock.patch(
        "secrets_shield.cli.install.get_global_hook_dir_path",
        return_value="global/hooks",
    ):
        yield


def test_scan_file(snapshot, cli_fs_runner):
    os.system('echo "This is a file with no secrets." > file')
    assert os.path.isfile("file")

    result = cli_fs_runner.invoke(cli, ["scan", "file"])
    assert result.exit_code == 0
    assert "No secrets have been found" in result.output


class TestScanFiles:
    def create_files(self):
        os.system('echo "This is a file with no secrets." > file1')
        os.system('echo "This is a file with no secrets." > file2')

    def test_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["scan", "file1", "file2"], input="n\n")
        assert result.exit_code == 1
        assert result.exception
        assert "Aborted!" in result.output

    def test_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["scan", "file1", "file2", "-r", "-y"])
        assert result.exit_code == 0
        assert "No secrets have been found" in result.output

    def test_verbose(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["scan", "file1", "file2", "-r", "-v"], input="y\n"
        )
        assert result.exit_code == 0
        assert "file1\n" in result.output
        assert "file2\n" in result.output
        assert "No secrets have been found" in result.output

    def test_verbose_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(
            cli, ["scan", "file1", "file2", "-r", "-v"], input="n\n"
        )
        assert result.exit_code == 1
        assert result.exception
        assert "Aborted!" in result.output

    def test_verbose_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["scan", "file1", "file2", "-r", "-v", "-y"])
        assert result.exit_code == 0
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

    def test_error(self, cli_fs_runner):
        result = cli_fs_runner.invoke(cli, ["scan", "./"])
        assert result.exit_code == 1
        assert result.exception
        assert "Error: Could not open file" in result.output

    def test_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["scan", "./", "-r"], input="n\n")
        assert result.exit_code == 1
        assert result.exception
        assert "Aborted!" in result.output

    def test_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["scan", "./", "-r", "-y"])
        assert result.exit_code == 0
        assert "No secrets have been found" in result.output

    def test_verbose(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["scan", "./", "-r", "-v"], input="y\n")
        assert result.exit_code == 0
        assert "file1\n" in result.output
        assert "dir/file2\n" in result.output
        assert "dir/subdir/file3\n" in result.output
        assert "No secrets have been found" in result.output

    def test_verbose_abort(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["scan", "./", "-r", "-v"], input="n\n")
        assert result.exit_code == 1
        assert result.exception
        assert "Aborted!" in result.output

    def test_verbose_yes(self, cli_fs_runner):
        self.create_files()
        result = cli_fs_runner.invoke(cli, ["scan", "./", "-r", "-v", "-y"])
        assert result.exit_code == 0
        assert "file1\n" in result.output
        assert "dir/file2\n" in result.output
        assert "dir/subdir/file3\n" in result.output
        assert "No secrets have been found" in result.output


class TestInstallLocal:
    def test_exit_is_dir(self, cli_fs_runner):
        os.makedirs(".git/hooks/pre-commit/")
        assert os.path.isdir(".git/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install"])
        os.system("rm -R .git/hooks/pre-commit")
        assert result.exit_code == 1
        assert result.exception
        assert "Error: .git/hooks/pre-commit is a directory" in result.output

    def test_not_exist(self, cli_fs_runner):
        assert not os.path.isfile(".git/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install"])
        assert os.path.isfile(".git/hooks/pre-commit")
        assert result.exit_code == 0
        assert "pre-commit successfully added in .git/hooks/pre-commit" in result.output

    def test_exist_not_force(self, cli_fs_runner):
        os.makedirs(".git/hooks", exist_ok=True)
        os.system('echo "pre-commit file" > .git/hooks/pre-commit')
        assert os.path.isfile(".git/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install"])
        assert result.exit_code == 1
        assert result.exception
        assert "Error: .git/hooks/pre-commit already exists." in result.output

    def test_exist_force(self, cli_fs_runner):
        os.makedirs(".git/hooks", exist_ok=True)
        os.system('echo "pre-commit file" > .git/hooks/pre-commit')
        assert os.path.isfile(".git/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-f"])
        assert result.exit_code == 0
        assert "pre-commit successfully added in .git/hooks/pre-commit" in result.output


class TestInstallGlobal:
    def test_exist_is_dir(self, cli_fs_runner, mockHookDirPath):
        os.makedirs("global/hooks/pre-commit/")
        assert os.path.isdir("global/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install"])
        os.system("rm -R global/hooks/pre-commit")
        assert result.exit_code == 1
        assert result.exception

    def test_not_exist(self, cli_fs_runner, mockHookDirPath):
        assert not os.path.isfile("global/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-g"])
        assert os.path.isfile("global/hooks/pre-commit")
        assert result.exit_code == 0
        assert (
            "pre-commit successfully added in global/hooks/pre-commit" in result.output
        )

    def test_exist_not_force(self, cli_fs_runner, mockHookDirPath):
        os.makedirs("global/hooks", exist_ok=True)
        os.system('echo "pre-commit file" > global/hooks/pre-commit')
        assert os.path.isfile("global/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-g"])
        assert result.exit_code == 1
        assert result.exception
        assert "Error: global/hooks/pre-commit already exists." in result.output

    def test_exist_force(self, cli_fs_runner, mockHookDirPath):
        os.makedirs("global/hooks", exist_ok=True)
        os.system('echo "pre-commit file" > global/hooks/pre-commit')
        assert os.path.isfile("global/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-g", "-f"])
        assert result.exit_code == 0
        assert (
            "pre-commit successfully added in global/hooks/pre-commit" in result.output
        )
