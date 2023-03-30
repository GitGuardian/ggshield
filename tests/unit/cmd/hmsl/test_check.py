from uuid import uuid4

from click.testing import CliRunner

from ggshield.cmd.main import cli
from tests.unit.conftest import assert_invoke_ok, my_vcr


@my_vcr.use_cassette
def test_hmsl_check_random_secret(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a random
    WHEN running the check command on it
    THEN we should not find a match
    """
    non_matching_secret = str(uuid4())
    with open("secrets.txt", "w") as f:
        f.write(non_matching_secret + "\n")

    result = cli_fs_runner.invoke(cli, ["hmsl", "check", "secrets.txt"])

    assert "Found 0 leaked secrets" in result.output
    assert_invoke_ok(result)


@my_vcr.use_cassette
def test_hmsl_check_common_secret(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a random
    WHEN running the check command on it
    THEN we should not find a match
    """
    with open("secrets.txt", "w") as f:
        f.write("password\n")

    result = cli_fs_runner.invoke(
        cli, ["hmsl", "check", "-n", "cleartext", "secrets.txt"]
    )

    assert "Found 1 leaked secret" in result.output
    assert "password" in result.output
    assert_invoke_ok(result)


@my_vcr.use_cassette
def test_hmsl_check_full_hash(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN a random
    WHEN running the check command on it
    THEN we should not find a match
    """
    with open("secrets.txt", "w") as f:
        f.write("password\n")

    result = cli_fs_runner.invoke(
        cli, ["hmsl", "check", "-f", "-n", "cleartext", "secrets.txt"]
    )

    assert "Found 1 leaked secret" in result.output
    assert "password" in result.output
    assert_invoke_ok(result)
