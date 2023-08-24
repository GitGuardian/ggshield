from pathlib import Path

import pytest
from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.cmd.hmsl.decrypt import load_mapping
from ggshield.verticals.hmsl.client import PREFIX_LENGTH
from ggshield.verticals.hmsl.crypto import hash_string
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok


ENV_FILE = r"""
FOO=bar
PASSWORD=1234
# Don't take "export" into account
export SECRET=foo

this line does not contain a secret

# Commented secrets should be detected
# BAR=prod123
# But comments should be ignored
BAZ=spam # eggs
# All at once
   # FOOBAR=toto42 # a super secret

# Quotes should be ignored
PASSWORD2="123v4@!,asTd"  # ggignore
export PASSWORD3="P@ssw0rd3"  # ggignore
export PASSWORD4="secret with spaces"
export PASSWORD5="escaped \" quote"
PASSWORD6="another escaped \" quote" # and "quotes" in comments afterwards
# Empty secret
PASSWORD7=""

# Ignored common values
KEY1=1
KEY2=0
KEY3=true
KEY4=false
KEY5=on
KEY6=off
KEY7=yes
KEY8=no
KEY9=enabled
KEY10=disabled
KEY11=none
KEY12=null

# Ignored keys
HOST=123.4.56.7
PORT=8080

# Be permissive on case and spaces
 a_secret = its_value

# A last one just in case
LAST=aBcD1234!@#$
"""


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


@pytest.fixture
def expected_from_env_file(cli_fs_runner):
    with open(".env", "w") as f:
        f.write(ENV_FILE)
    return {
        "FOO": "bar",
        "PASSWORD": "1234",
        "SECRET": "foo",
        "BAZ": "spam",
        "PASSWORD2": "123v4@!,asTd",  # ggignore
        "PASSWORD3": "P@ssw0rd3",  # ggignore
        "PASSWORD4": "secret with spaces",
        "PASSWORD5": 'escaped " quote',
        "PASSWORD6": 'another escaped " quote',
        "a_secret": "its_value",
        "LAST": "aBcD1234!@#$",
    }


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


def test_hmsl_fingerprint_env_file(
    cli_fs_runner: CliRunner, expected_from_env_file
) -> None:
    """
    GIVEN a .env file
    WHEN running the fingerprint command on it
    THEN the keys and secrets are properly parsed
    """
    result = cli_fs_runner.invoke(
        cli, ["hmsl", "fingerprint", "-f", "-t", "env", ".env"]
    )
    assert_invoke_ok(result)
    expected_mapping = {hash_string(v): k for k, v in expected_from_env_file.items()}
    mapping = load_mapping(open("mapping.txt"))
    assert mapping == expected_mapping


def test_hmsl_fingerprint_env_file_cleartext(
    cli_fs_runner: CliRunner, expected_from_env_file
) -> None:
    """
    GIVEN a .env file
    WHEN using a different naming strategy
    THEN the mapping is written as expected
    """
    result = cli_fs_runner.invoke(
        cli, ["hmsl", "fingerprint", "-f", "-t", "env", "-n", "cleartext", ".env"]
    )
    assert_invoke_ok(result)
    expected_mapping = {
        hash_string(secret): secret for secret in expected_from_env_file.values()
    }
    mapping = load_mapping(open("mapping.txt"))
    assert mapping == expected_mapping
