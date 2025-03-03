from pathlib import Path
from uuid import uuid4

from click.testing import CliRunner

from ggshield.__main__ import cli
from tests.unit.conftest import assert_invoke_ok, my_vcr


@my_vcr.use_cassette
def test_hmsl_check_random_secret(cli_fs_runner: CliRunner, tmp_path: Path) -> None:
    """
    GIVEN a random secret
    WHEN running the check command on it
    THEN we should not find a match
    """
    non_matching_secret = str(uuid4())
    secrets_path = tmp_path / "secrets.txt"
    secrets_path.write_text(non_matching_secret)

    result = cli_fs_runner.invoke(cli, ["hmsl", "check", str(secrets_path)])
    assert_invoke_ok(result)
    assert "All right! No leaked secret has been found." in result.output


@my_vcr.use_cassette
def test_hmsl_check_common_secret(cli_fs_runner: CliRunner, tmp_path: Path) -> None:
    """
    GIVEN a common secret
    WHEN running the check command on it
    THEN we do find matches
    """
    secrets_path = tmp_path / "secrets.txt"
    secrets_path.write_text("password")

    result = cli_fs_runner.invoke(
        cli, ["hmsl", "check", "-n", "cleartext", str(secrets_path)]
    )

    assert "Found 1 leaked secret" in result.output
    assert "password" in result.output
    assert_invoke_ok(result)


@my_vcr.use_cassette
def test_hmsl_check_full_hash(cli_fs_runner: CliRunner, tmp_path: Path) -> None:
    """
    GIVEN a common secret
    WHEN running the check command on it with full hash option
    THEN we do find matches
    """
    secrets_path = tmp_path / "secrets.txt"
    secrets_path.write_text("password")

    result = cli_fs_runner.invoke(
        cli, ["hmsl", "check", "-f", "-n", "cleartext", str(secrets_path)]
    )
    assert "Found 1 leaked secret" in result.output
    assert "password" in result.output
    assert_invoke_ok(result)
