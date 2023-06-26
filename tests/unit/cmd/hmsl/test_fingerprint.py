from pathlib import Path

import pytest
from click.testing import CliRunner

from ggshield.cmd.main import cli
from ggshield.hmsl.client import PREFIX_LENGTH
from ggshield.hmsl.crypto import hash_string
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok


@pytest.fixture
def secrets():
    """Prepare a file with some secrets"""
    return ["foo", "bar", "password", "1234"]


@pytest.fixture
def secrets_path(secrets, tmp_path: Path):
    secrets_path = tmp_path / "secrets.txt"
    # add an empty line
    lines = secrets[:2] + [""] + secrets[2:]
    secrets_path.write_text("\n".join(lines))
    return secrets_path


def test_hmsl_fingerprint_no_file(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN some secrets
    WHEN running the fingerprint command with no argument
    THEN the return code is 2
    """
    result = cli_fs_runner.invoke(cli, ["hmsl", "fingerprint"])
    assert_invoke_exited_with(result, 2)


def test_hmsl_fingerprint_no_file_2(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN some secrets
    WHEN running the fingerprint command with a non-existing file
    THEN the return code is 2
    """
    result = cli_fs_runner.invoke(cli, ["hmsl", "fingerprint" "none.txt"])
    assert_invoke_exited_with(result, 2)


def test_hmsl_fingerprint_default_behavior(
    cli_fs_runner: CliRunner, secrets, secrets_path
) -> None:
    """
    GIVEN some secrets
    WHEN running the fingerprint command on a file
    THEN the secrets are correctly prepared
    """
    result = cli_fs_runner.invoke(cli, ["hmsl", "fingerprint", str(secrets_path)])
    assert_invoke_ok(result)
    # Payload is a set of prefixes
    prepared = set(open("payload.txt").read().split("\n")) - {""}
    assert {hash_string(secret)[:PREFIX_LENGTH] for secret in secrets} == prepared
    # Mapping contains the full hashes and hints
    raw_mapping = set(open("mapping.txt").read().split("\n")) - {""}
    mapping = {line.partition(":")[0]: line.partition(":")[2] for line in raw_mapping}
    assert {hash_string(secret) for secret in secrets} == mapping.keys()
    assert all("*" in name for name in mapping.values())


def test_hmsl_fingerprint_full_hashes(
    cli_fs_runner: CliRunner, secrets, secrets_path
) -> None:
    """
    GIVEN some secrets
    WHEN running the fingerprint command on a file
         with the --full-hashes flag
    THEN the payload contains hashes
    """
    result = cli_fs_runner.invoke(cli, ["hmsl", "fingerprint", "-f", str(secrets_path)])
    assert_invoke_ok(result)
    # Payload is a set of prefixes
    prepared = set(open("payload.txt").read().split("\n")) - {""}
    assert {hash_string(secret) for secret in secrets} == prepared


def test_hmsl_fingerprint_cleartext(
    cli_fs_runner: CliRunner, secrets, secrets_path
) -> None:
    """
    GIVEN some secrets
    WHEN running the fingerprint command on a file
         with a cleartext strategy
    THEN the mapping contains the secrets
    """
    result = cli_fs_runner.invoke(
        cli, ["hmsl", "fingerprint", "-n", "cleartext", str(secrets_path)]
    )
    assert_invoke_ok(result)
    # Payload is a set of prefixes
    mapping = set(open("mapping.txt").read().split("\n")) - {""}
    names = {line.partition(":")[2] for line in mapping}
    assert names == set(secrets)


def test_hmsl_fingerprint_none(cli_fs_runner: CliRunner, secrets, secrets_path) -> None:
    """
    GIVEN some secrets
    WHEN running the fingerprint command on a file
         with the none strategy
    THEN the mapping only contains hashes
    """
    result = cli_fs_runner.invoke(
        cli, ["hmsl", "fingerprint", "-n", "none", str(secrets_path)]
    )
    assert_invoke_ok(result)
    # Payload is a set of prefixes
    assert ":" not in open("mapping.txt").read()


@pytest.mark.parametrize(
    "prefix, expected", [("toto", "toto-"), ("toto-", "toto-"), ("", "")]
)
def test_hmsl_fingerprint_prefix(
    cli_fs_runner: CliRunner, secrets_path, prefix, expected
) -> None:
    """
    GIVEN some secrets
    WHEN running the fingerprint command on a file
         with a prefix
    THEN the output files have the proper name
    """
    result = cli_fs_runner.invoke(
        cli, ["hmsl", "fingerprint", "-p", prefix, str(secrets_path)]
    )
    assert_invoke_ok(result)
    assert Path(f"{expected}payload.txt").exists()
