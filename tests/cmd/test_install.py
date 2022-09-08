import os
from pathlib import Path
from unittest import mock
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from ggshield.cmd.main import cli
from tests.conftest import assert_invoke_exited_with, assert_invoke_ok


SAMPLE_PRE_COMMIT = """#!/bin/bash


ggshield secret scan pre-commit
"""

SAMPLE_PRE_PUSH = """#!/bin/bash


ggshield secret scan pre-push
"""


@pytest.fixture(scope="class")
def mockHookDirPath():
    with mock.patch(
        "ggshield.cmd.install.get_global_hook_dir_path", return_value="global/hooks"
    ):
        yield


class TestInstallLocal:
    def test_local_exist_is_dir(self, cli_fs_runner):
        os.system("git init")
        os.makedirs(".git/hooks/pre-commit/")
        assert os.path.isdir(".git/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-m", "local"])
        os.system("rm -R .git/hooks/pre-commit")
        assert_invoke_exited_with(result, 1)
        assert result.exception
        assert "Error: .git/hooks/pre-commit is a directory" in result.output

    def test_local_exist_not_force(self, cli_fs_runner):
        os.system("git init")
        os.makedirs(".git/hooks", exist_ok=True)
        Path(".git/hooks/pre-commit").write_text("pre-commit file")
        assert os.path.isfile(".git/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-m", "local"])
        assert_invoke_exited_with(result, 1)
        assert result.exception
        assert "Error: .git/hooks/pre-commit already exists." in result.output

    def test_local_exist_force(self, cli_fs_runner):
        os.system("git init")
        os.makedirs(".git/hooks", exist_ok=True)
        Path(".git/hooks/pre-commit").write_text("pre-commit file")
        assert os.path.isfile(".git/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-f", "-m", "local"])
        assert_invoke_ok(result)
        assert "pre-commit successfully added in .git/hooks/pre-commit" in result.output

    @patch("ggshield.cmd.install.check_git_dir")
    def test_precommit_install(
        self,
        check_dir_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN None
        WHEN the command is run
        THEN it should create a pre-commit git hook script
        """

        result = cli_fs_runner.invoke(
            cli,
            ["install", "-m", "local"],
        )
        hook = open(".git/hooks/pre-commit", "r")
        hook_str = hook.read()
        assert SAMPLE_PRE_COMMIT == hook_str

        assert (
            "pre-commit successfully added in .git/hooks/pre-commit\n" in result.output
        )
        assert_invoke_ok(result)

    @pytest.mark.parametrize("hook_type", ["pre-push", "pre-commit"])
    @patch("ggshield.cmd.install.check_git_dir")
    def test_install_exists(
        self,
        check_dir_mock: Mock,
        hook_type: str,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a hook that already exists
        WHEN the command is run without --force or --append
        THEN it should error
        """
        os.makedirs(".git/hooks/", exist_ok=True)
        with open(f".git/hooks/{hook_type}", "w") as f:
            f.write("#!/bin/bash\nsample-command\n")

        result = cli_fs_runner.invoke(
            cli,
            ["install", "-m", "local", "-t", hook_type],
        )

        assert (
            "already exists. Use --force to override or --append to add to current script\n"
            in result.output
        )
        assert_invoke_exited_with(result, 1)

    @pytest.mark.parametrize("hook_type", ["pre-push", "pre-commit"])
    @patch("ggshield.cmd.install.check_git_dir")
    def test_install_exists_force(
        self,
        check_dir_mock: Mock,
        hook_type: str,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a hook that already exists
        WHEN the command is run with --force
        THEN it should return 0 and install the hook
        """
        os.makedirs(".git/hooks/", exist_ok=True)
        with open(f".git/hooks/{hook_type}", "w") as f:
            f.write("#!/bin/bash\nsample-command\n")

        result = cli_fs_runner.invoke(
            cli,
            ["install", "-m", "local", "-t", hook_type, "--force"],
        )

        assert (
            f"{hook_type} successfully added in .git/hooks/{hook_type}\n"
            in result.output
        )
        assert_invoke_ok(result)

    @pytest.mark.parametrize("hook_type", ["pre-push", "pre-commit"])
    @patch("ggshield.cmd.install.check_git_dir")
    def test_install_exists_append(
        self,
        check_dir_mock: Mock,
        hook_type: str,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a hook that already exists
        WHEN the command is run with --append
        THEN it should return 0 and append the hook to the existing one
        """
        os.makedirs(".git/hooks/", exist_ok=True)
        with open(f".git/hooks/{hook_type}", "w") as f:
            f.write("#!/bin/bash\nsample-command\n")

        result = cli_fs_runner.invoke(
            cli,
            ["install", "-m", "local", "-t", hook_type, "--append"],
        )
        hook = open(f".git/hooks/{hook_type}", "r")
        hook_str = hook.read()
        assert "sample-command" in hook_str
        assert "ggshield secret scan" in hook_str

        assert (
            f"{hook_type} successfully added in .git/hooks/{hook_type}\n"
            in result.output
        )
        assert_invoke_ok(result)

    @patch("ggshield.cmd.install.check_git_dir")
    def test_prepush_install(
        self,
        check_dir_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN None
        WHEN the command is run
        THEN it should create a pre-push git hook script
        """

        result = cli_fs_runner.invoke(
            cli,
            ["install", "-m", "local", "-t", "pre-push"],
        )
        hook = open(".git/hooks/pre-push", "r")
        hook_str = hook.read()
        assert SAMPLE_PRE_PUSH == hook_str

        assert "pre-push successfully added in .git/hooks/pre-push\n" in result.output
        assert_invoke_ok(result)


class TestInstallGlobal:
    def test_global_exist_is_dir(self, cli_fs_runner, mockHookDirPath):
        os.makedirs("global/hooks/pre-commit/")
        assert os.path.isdir("global/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-m", "global"])
        os.system("rm -R global/hooks/pre-commit")
        assert_invoke_exited_with(result, 1)
        assert result.exception

    def test_global_not_exist(self, cli_fs_runner, mockHookDirPath):
        assert not os.path.isfile("global/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-m", "global"])
        assert os.path.isfile("global/hooks/pre-commit")
        assert_invoke_ok(result)
        assert (
            "pre-commit successfully added in global/hooks/pre-commit" in result.output
        )

    @pytest.mark.parametrize("hook_type", ["pre-push", "pre-commit"])
    @patch("ggshield.cmd.install.get_global_hook_dir_path")
    def test_install_global(
        self,
        get_global_hook_dir_path_mock: Mock,
        hook_type: str,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN None
        WHEN the command is run
        THEN it should create a pre-push git hook script in the global path
        """
        path = "global_hooks"
        get_global_hook_dir_path_mock.return_value = path
        result = cli_fs_runner.invoke(
            cli,
            ["install", "-m", "global", "-t", hook_type],
        )

        hook = open(f"{path}/{hook_type}", "r")
        hook_str = hook.read()
        assert f"if [[ -f .git/hooks/{hook_type} ]]; then" in hook_str
        assert f"ggshield secret scan {hook_type}" in hook_str

        assert (
            f"{hook_type} successfully added in global_hooks/{hook_type}\n"
            in result.output
        )
        assert_invoke_ok(result)

    def test_global_exist_not_force(self, cli_fs_runner, mockHookDirPath):
        os.makedirs("global/hooks", exist_ok=True)
        Path("global/hooks/pre-commit").write_text("pre-commit file")
        assert os.path.isfile("global/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-m", "global"])
        assert_invoke_exited_with(result, 1)
        assert result.exception
        assert "Error: global/hooks/pre-commit already exists." in result.output

    def test_global_exist_force(self, cli_fs_runner, mockHookDirPath):
        os.makedirs("global/hooks", exist_ok=True)
        Path("global/hooks/pre-commit").write_text("pre-commit file")
        assert os.path.isfile("global/hooks/pre-commit")

        result = cli_fs_runner.invoke(cli, ["install", "-m", "global", "-f"])
        assert_invoke_ok(result)
        assert (
            "pre-commit successfully added in global/hooks/pre-commit" in result.output
        )
