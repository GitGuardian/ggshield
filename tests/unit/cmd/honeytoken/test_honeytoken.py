from click.testing import CliRunner

from ggshield.cmd.main import cli
from ggshield.core.errors import ExitCode
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok, my_vcr


@my_vcr.use_cassette("test_honeytoken_create_no_argument")
def test_honeytokens_create_no_arg(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN -
    WHEN running the honeytoken command with no argument
    THEN the return code is 2
    """

    result = cli_fs_runner.invoke(
        cli,
        [
            "honeytoken",
            "create",
        ],
    )
    assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)


@my_vcr.use_cassette("test_honeytoken_create_ok_no_name")
def test_honeytoken_create_ok_no_name(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN -
    WHEN running the honeytoken command with no name
    THEN the return code is 0 and a name is generated
    """

    result = cli_fs_runner.invoke(
        cli,
        ["honeytoken", "create", "--description", "description", "--type", "AWS"],
    )
    assert_invoke_ok(result)


@my_vcr.use_cassette("test_honeytoken_create_ok")
def test_honeytoken_create_ok(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN -
    WHEN running the honeytoken command with all needed arguments
    THEN the return code is 0
    """

    result = cli_fs_runner.invoke(
        cli,
        [
            "honeytoken",
            "create",
            "--description",
            "description",
            "--type",
            "AWS",
            "--name",
            "test_honey_token",
        ],
    )
    assert_invoke_ok(result)


@my_vcr.use_cassette("test_honeytoken_create_error_403")
def test_honeytoken_create_error_403(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a token without honeytoken scope
    WHEN running the honeytoken command with all needed arguments
    THEN the return code is 1 and the error message match the needed message
    """

    result = cli_fs_runner.invoke(
        cli,
        [
            "honeytoken",
            "create",
            "--description",
            "description",
            "--type",
            "AWS",
            "--name",
            "test_honey_token_error_403",
        ],
    )
    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert "ggshield does not have permissions to create honeytokens" in result.stdout
