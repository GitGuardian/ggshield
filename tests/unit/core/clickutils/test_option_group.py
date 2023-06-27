from typing import Any

import click
from click.testing import CliRunner

from ggshield.core.clickutils.option_group import OptionGroup
from ggshield.core.errors import ExitCode


@click.group()
def cli():
    pass


@cli.command(name="test-option-group")
@click.option(
    "--one",
    is_flag=True,
    cls=OptionGroup,
    not_required_if=["two", "three"],
)
@click.option(
    "--two",
    is_flag=True,
    cls=OptionGroup,
    not_required_if=["one", "three"],
)
@click.option(
    "--three",
    is_flag=True,
    cls=OptionGroup,
    not_required_if=["one", "two"],
)
@click.option(
    "--other",
    is_flag=True,
)
def exclusive_options_cmd(
    **kwargs: Any,
) -> int:
    click.echo("Successfully called the test function")
    return ExitCode.SUCCESS


def test_option_group_no_option(cli_fs_runner: CliRunner):
    # GIVEN a command with 3 options in an OptionGroup
    # WHEN invoking the command with no option from the group
    result = cli_fs_runner.invoke(cli, ["test-option-group"])
    # THEN command fails with usage error
    assert result.exit_code == ExitCode.USAGE_ERROR


def test_option_group_too_many_options(cli_fs_runner: CliRunner):
    # GIVEN a command with 3 options in an OptionGroup
    # WHEN invoking the command with more than one option from the group
    result1 = cli_fs_runner.invoke(cli, ["test-option-group", "--one", "--two"])
    result2 = cli_fs_runner.invoke(
        cli, ["test-option-group", "--one", "--two", "--three"]
    )
    # THEN command fails with usage error
    assert result1.exit_code == ExitCode.USAGE_ERROR
    assert result2.exit_code == ExitCode.USAGE_ERROR


def test_option_group_one_option(cli_fs_runner: CliRunner):
    # GIVEN a command with 3 options in an OptionGroup
    # WHEN invoking the command with more than one option from the group
    result1 = cli_fs_runner.invoke(cli, ["test-option-group", "--one"])
    result2 = cli_fs_runner.invoke(cli, ["test-option-group", "--one", "--other"])
    # THEN command fails with usage error
    assert result1.exit_code == ExitCode.SUCCESS
    assert result2.exit_code == ExitCode.SUCCESS
