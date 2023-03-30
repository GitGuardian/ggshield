from click.testing import CliRunner

from ggshield.cmd.main import cli
from tests.unit.conftest import assert_invoke_ok, my_vcr


@my_vcr.use_cassette
def test_hmsl_query_prefix(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a random
    WHEN running the check command on it
    THEN we should not find a match
    """
    with open("payload.txt", "w") as f:
        f.write("743d9\n")

    result = cli_fs_runner.invoke(cli, ["hmsl", "query", "payload.txt"])

    assert "password" not in result.output  # encrypted
    assert "payload" in result.output
    assert_invoke_ok(result)


@my_vcr.use_cassette
def test_hmsl_query_hash(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a random
    WHEN running the check command on it
    THEN we should not find a match
    """
    with open("payload.txt", "w") as f:
        f.write("743d9fde380b7064cc6a8d3071184fc47905cf7440e5615cd46c7b6cbfb46d47\n")

    result = cli_fs_runner.invoke(cli, ["hmsl", "query", "payload.txt"])

    assert "github.com" in result.output  # already decrypted

    assert_invoke_ok(result)
