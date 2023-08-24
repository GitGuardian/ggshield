from pathlib import Path

import pytest
from click.testing import CliRunner

from ggshield.__main__ import cli
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok, my_vcr


@pytest.fixture(autouse=True)
def use_staging_env(monkeypatch):
    # The cassettes where recorded before the service was operational in production
    monkeypatch.setenv(
        "GITGUARDIAN_HMSL_URL", "https://hasmysecretleaked.staging.gitguardian.tech"
    )
    monkeypatch.delenv("GITGUARDIAN_API_KEY", raising=False)


@my_vcr.use_cassette
def test_hmsl_query_prefix(cli_fs_runner: CliRunner, tmp_path: Path) -> None:
    """
    GIVEN a common prefix
    WHEN running the check command on it
    THEN we should find a match
    """
    payload_path = tmp_path / "payload.txt"
    payload_path.write_text("743d9")

    result = cli_fs_runner.invoke(cli, ["hmsl", "query", str(payload_path)])

    assert "password" not in result.output  # encrypted
    assert "payload" in result.output
    assert_invoke_ok(result)


@my_vcr.use_cassette
def test_hmsl_query_hash(cli_fs_runner: CliRunner, tmp_path: Path) -> None:
    """
    GIVEN a common hash
    WHEN running the check command on it
    THEN we should find a match
    """
    payload_path = tmp_path / "payload.txt"
    payload_path.write_text(
        "743d9fde380b7064cc6a8d3071184fc47905cf7440e5615cd46c7b6cbfb46d47"
    )
    result = cli_fs_runner.invoke(cli, ["hmsl", "query", str(payload_path)])
    assert_invoke_ok(result)
    assert "github.com" in result.output  # already decrypted


def test_bad_payload(cli_fs_runner: CliRunner, tmp_path: Path) -> None:
    """
    GIVEN an invalid payload
    WHEN running the check command on it
    THEN we should get an error
    """
    payload_path = tmp_path / "payload.txt"
    payload_path.write_text("foo")
    result = cli_fs_runner.invoke(cli, ["hmsl", "query", str(payload_path)])
    assert_invoke_exited_with(result, 128)
