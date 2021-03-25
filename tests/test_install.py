import os
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from ggshield.cmd import cli


SAMPLE_PRE_COMMIT = """#!/bin/bash


ggshield scan pre-commit
"""

SAMPLE_PRE_PUSH = """#!/bin/bash


ggshield scan pre-push
"""


@patch("ggshield.install.check_git_dir")
def test_precommit_install(
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

    assert "pre-commit successfully added in .git/hooks/pre-commit\n" in result.output
    assert result.exit_code == 0


@pytest.mark.parametrize("hook_type", ["pre-push", "pre-commit"])
@patch("ggshield.install.check_git_dir")
def test_install_exists(
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
    assert result.exit_code == 1


@pytest.mark.parametrize("hook_type", ["pre-push", "pre-commit"])
@patch("ggshield.install.check_git_dir")
def test_install_exists_force(
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
        f"{hook_type} successfully added in .git/hooks/{hook_type}\n" in result.output
    )
    assert result.exit_code == 0


@pytest.mark.parametrize("hook_type", ["pre-push", "pre-commit"])
@patch("ggshield.install.check_git_dir")
def test_install_exists_append(
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
    assert "ggshield scan" in hook_str

    assert (
        f"{hook_type} successfully added in .git/hooks/{hook_type}\n" in result.output
    )
    assert result.exit_code == 0


@patch("ggshield.install.check_git_dir")
def test_prepush_install(
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
    assert result.exit_code == 0


@pytest.mark.parametrize("hook_type", ["pre-push", "pre-commit"])
@patch("ggshield.install.get_global_hook_dir_path")
def test_install_global(
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
    assert f"ggshield scan {hook_type}" in hook_str

    assert (
        f"{hook_type} successfully added in global_hooks/{hook_type}\n" in result.output
    )
    assert result.exit_code == 0
