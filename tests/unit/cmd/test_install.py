import os
from pathlib import Path
from unittest import mock
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok


SAMPLE_PRE_COMMIT = """#!/bin/sh
ggshield secret scan pre-commit "$@"
"""

SAMPLE_PRE_PUSH = """#!/bin/sh
ggshield secret scan pre-push "$@"
"""


@pytest.fixture(scope="class")
def mockHookDirPath():
    with mock.patch(
        "ggshield.cmd.install.get_global_hook_dir_path",
        return_value=Path("global/hooks"),
    ):
        yield


class TestInstallLocal:
    def test_local_exist_is_dir(self, cli_fs_runner):
        os.system("git init")
        hook_path = Path(".git/hooks/pre-commit")
        hook_path.mkdir()

        result = cli_fs_runner.invoke(cli, ["install", "-m", "local"])
        assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
        assert result.exception
        assert f"Error: {hook_path} is a directory" in result.output

    def test_local_exist_not_force(self, cli_fs_runner):
        os.system("git init")
        hook_path = Path(".git/hooks/pre-commit")
        hook_path.write_text("pre-commit file")

        result = cli_fs_runner.invoke(cli, ["install", "-m", "local"])
        assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
        assert result.exception
        assert f"Error: {hook_path} already exists." in result.output

    def test_local_exist_force(self, cli_fs_runner):
        os.system("git init")
        hook_path = Path(".git/hooks/pre-commit")
        hook_path.write_text("pre-commit file")

        result = cli_fs_runner.invoke(cli, ["install", "-f", "-m", "local"])
        assert_invoke_ok(result)
        assert f"pre-commit successfully added in {hook_path}" in result.output

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
        hook_path = Path(".git/hooks/pre-commit")
        hook_str = hook_path.read_text()
        assert hook_str == SAMPLE_PRE_COMMIT

        assert f"pre-commit successfully added in {hook_path}\n" in result.output
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
        hook_path = Path(".git/hooks") / hook_type
        hook_path.parent.mkdir(parents=True)
        hook_path.write_text("#!/bin/bash\nsample-command\n")

        result = cli_fs_runner.invoke(
            cli,
            ["install", "-m", "local", "-t", hook_type],
        )

        assert (
            "already exists. Use --force to override or --append to add to current script\n"
            in result.output
        )
        assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)

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
        hook_path = Path(".git/hooks") / hook_type
        hook_path.parent.mkdir(parents=True)
        hook_path.write_text("#!/bin/bash\nsample-command\n")

        result = cli_fs_runner.invoke(
            cli,
            ["install", "-m", "local", "-t", hook_type, "--force"],
        )

        assert f"{hook_type} successfully added in {hook_path}\n" in result.output
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
        hook_path = Path(".git/hooks") / hook_type
        hook_path.parent.mkdir(parents=True)
        hook_path.write_text("#!/bin/bash\nsample-command\n")

        result = cli_fs_runner.invoke(
            cli,
            ["install", "-m", "local", "-t", hook_type, "--append"],
        )
        hook_str = hook_path.read_text()
        assert "sample-command" in hook_str
        assert "ggshield secret scan" in hook_str

        assert f"{hook_type} successfully added in {hook_path}\n" in result.output
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
        hook_path = Path(".git/hooks/pre-push")
        hook_str = hook_path.read_text()
        assert hook_str == SAMPLE_PRE_PUSH

        assert f"pre-push successfully added in {hook_path}\n" in result.output
        assert_invoke_ok(result)


class TestInstallGlobal:
    def test_global_exist_is_dir(self, cli_fs_runner, mockHookDirPath):
        global_hook_path = Path("global/hooks/pre-commit")
        global_hook_path.mkdir(parents=True)

        result = cli_fs_runner.invoke(cli, ["install", "-m", "global"])
        assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
        assert result.exception

    def test_global_not_exist(self, cli_fs_runner, mockHookDirPath):
        global_hook_path = Path("global/hooks/pre-commit")
        assert not global_hook_path.exists()

        result = cli_fs_runner.invoke(cli, ["install", "-m", "global"])
        assert global_hook_path.is_file()
        assert_invoke_ok(result)
        assert f"pre-commit successfully added in {global_hook_path}" in result.output

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
        global_hooks_dir = Path("global_hooks")
        get_global_hook_dir_path_mock.return_value = global_hooks_dir
        result = cli_fs_runner.invoke(
            cli,
            ["install", "-m", "global", "-t", hook_type],
        )

        hook_path = global_hooks_dir / hook_type
        hook_str = hook_path.read_text()
        assert f"if [ -f .git/hooks/{hook_type} ]; then" in hook_str
        assert f"ggshield secret scan {hook_type}" in hook_str

        assert f"{hook_type} successfully added in {hook_path}\n" in result.output
        assert_invoke_ok(result)

    def test_global_exist_not_force(self, cli_fs_runner, mockHookDirPath):
        hook_path = Path("global/hooks/pre-commit")
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text("pre-commit file")
        assert hook_path.is_file()

        result = cli_fs_runner.invoke(cli, ["install", "-m", "global"])
        assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
        assert result.exception
        assert f"Error: {hook_path} already exists." in result.output

    def test_global_exist_force(self, cli_fs_runner, mockHookDirPath):
        hook_path = Path("global/hooks/pre-commit")
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text("pre-commit file")
        assert hook_path.is_file()

        result = cli_fs_runner.invoke(cli, ["install", "-m", "global", "-f"])
        assert_invoke_ok(result)
        assert f"pre-commit successfully added in {hook_path}" in result.output
