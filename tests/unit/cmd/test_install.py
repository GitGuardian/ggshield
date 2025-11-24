import os
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.cmd.install import get_default_global_hook_dir_path, install_local
from ggshield.core.errors import ExitCode
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok


SAMPLE_PRE_COMMIT = """#!/bin/sh
ggshield secret scan pre-commit "$@"
"""

SAMPLE_PRE_PUSH = """#!/bin/sh
ggshield secret scan pre-push "$@"
"""


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

    @patch("ggshield.cmd.install.check_git_dir")
    @patch("ggshield.cmd.install.git")
    def test_install_local_detects_husky(
        self,
        git_mock: Mock,
        check_dir_mock: Mock,
        cli_fs_runner: CliRunner,
    ):
        """
        GIVEN a repository configured with Husky (.husky/_ directory as hooks path)
        WHEN install_local is called
        THEN it should create the hook in .husky/pre-commit instead of .git/hooks
        """
        husky_dir = Path(".husky")
        husky_hooks_dir = husky_dir / "_"
        husky_hooks_dir.mkdir(parents=True)

        # Mock git to return .husky/_ as the local hooks path
        git_mock.return_value = ".husky/_"

        return_code = install_local(hook_type="pre-commit", force=False, append=False)

        assert return_code == 0

        # Hook should be in .husky/pre-commit, not .husky/_/pre-commit
        husky_hook = husky_dir / "pre-commit"
        assert husky_hook.is_file()
        assert 'ggshield secret scan pre-commit "$@"' in husky_hook.read_text()

        # Hook should NOT be in .git/hooks/pre-commit
        default_hook = Path(".git/hooks/pre-commit")
        assert not default_hook.exists()


@pytest.fixture()
def custom_global_git_config_path(tmp_path, monkeypatch):
    config_path = tmp_path / "global-git-config"
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config_path))
    yield config_path


class TestInstallGlobal:
    """
    These tests use the cli_runner fixture and not the cli_fs_runner one. The reason for
    this is they execute git commands and git commands are not run in the fake
    filesystem created by cli_fs_runner so the fake filesystem is useless here.
    """

    def test_global_exist_is_dir(
        self, cli_runner: CliRunner, custom_global_git_config_path: Path
    ):
        global_pre_commit_hook_path = get_default_global_hook_dir_path() / "pre-commit"
        global_pre_commit_hook_path.mkdir(parents=True)

        result = cli_runner.invoke(cli, ["install", "-m", "global"])
        assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
        assert result.exception

    def test_global_not_exist(self, cli_runner, custom_global_git_config_path: Path):
        global_pre_commit_hook_path = get_default_global_hook_dir_path() / "pre-commit"
        assert not global_pre_commit_hook_path.exists()

        result = cli_runner.invoke(cli, ["install", "-m", "global"])
        assert global_pre_commit_hook_path.is_file()
        assert_invoke_ok(result)
        assert (
            f"pre-commit successfully added in {global_pre_commit_hook_path}"
            in result.output
        )

    def test_install_custom_global_hook_dir(
        self, cli_runner: CliRunner, tmp_path: Path, custom_global_git_config_path: Path
    ):
        """
        GIVEN an existing global git config
        AND a custom value for core.hooksPath in the global git config
        WHEN `install -m global` is called
        THEN it installs the hook in the custom core.hooksPath dir
        """
        custom_hooks_dir = tmp_path / "custom-hooks-dir"
        custom_pre_commit_path = custom_hooks_dir / "pre-commit"
        custom_global_git_config_path.write_text(
            f"[core]\nhooksPath = {custom_hooks_dir.as_posix()}\n", encoding="utf-8"
        )

        result = cli_runner.invoke(cli, ["install", "-m", "global"])
        assert_invoke_ok(result)
        assert custom_pre_commit_path.is_file()
        assert (
            f"pre-commit successfully added in {custom_pre_commit_path}"
            in result.output
        )

    @pytest.mark.parametrize("hook_type", ["pre-push", "pre-commit"])
    def test_install_global(
        self,
        hook_type: str,
        cli_runner: CliRunner,
        custom_global_git_config_path: Path,
    ):
        """
        GIVEN None
        WHEN the command is run
        THEN it should create a pre-push git hook script in the global path
        """

        result = cli_runner.invoke(
            cli,
            ["install", "-m", "global", "-t", hook_type],
        )

        hook_path = get_default_global_hook_dir_path() / hook_type
        hook_str = hook_path.read_text()
        assert f"if [ -f .git/hooks/{hook_type} ]; then" in hook_str
        assert f"ggshield secret scan {hook_type}" in hook_str

        assert f"{hook_type} successfully added in {hook_path}\n" in result.output
        assert_invoke_ok(result)

    def test_global_exist_not_force(
        self, cli_runner: CliRunner, custom_global_git_config_path: Path
    ):
        """
        GIVEN a global hook dir with an exising pre-commit script
        WHEN install is called
        THEN it fails
        """
        hook_path = get_default_global_hook_dir_path() / "pre-commit"
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text("pre-commit file")
        assert hook_path.is_file()

        result = cli_runner.invoke(cli, ["install", "-m", "global"])
        assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
        assert result.exception
        assert f"Error: {hook_path} already exists." in result.output

    def test_global_exist_force(
        self, cli_runner: CliRunner, custom_global_git_config_path: Path
    ):
        """
        GIVEN a global hook dir with an exising pre-commit script
        WHEN install is called with -f
        THEN it ignores the fact that the pre-commit script exists and succeeds
        """
        hook_path = get_default_global_hook_dir_path() / "pre-commit"
        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text("pre-commit file")
        assert hook_path.is_file()

        result = cli_runner.invoke(cli, ["install", "-m", "global", "-f"])
        assert_invoke_ok(result)
        assert f"pre-commit successfully added in {hook_path}" in result.output
