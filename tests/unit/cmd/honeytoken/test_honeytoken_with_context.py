from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok, my_vcr


AWS_TYPE = "AWS"


def test_honeytokens_create_with_context_no_arg(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN -
    WHEN running the honeytoken command with no argument
    THEN the return code is 2
    """

    result = cli_fs_runner.invoke(
        cli,
        [
            "honeytoken",
            "create-with-context",
        ],
    )
    assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)


@my_vcr.use_cassette("test_honeytoken_create_with_context_ok_no_name")
def test_honeytoken_create_with_context_ok_no_name(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN -
    WHEN running the honeytoken command with no name
    THEN the return code is 0 and a name is generated
    """

    result = cli_fs_runner.invoke(
        cli,
        [
            "honeytoken",
            "create-with-context",
            "--description",
            "description",
            "--type",
            AWS_TYPE,
        ],
    )
    assert_invoke_ok(result)


@my_vcr.use_cassette("test_honeytoken_create_with_context_bad_language")
def test_honeytoken_create_with_context_bad_language(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a token without honeytoken scope
    WHEN running the honeytoken command with all needed arguments
    THEN the return code is UNEXPECTED_ERROR and the error message match the needed message
    """
    result = cli_fs_runner.invoke(
        cli,
        [
            "honeytoken",
            "create-with-context",
            "--description",
            "test_create_error",
            "--type",
            AWS_TYPE,
            "--language",
            "non_existing_language",
        ],
    )
    assert "Error: Language not recognized." in result.output
