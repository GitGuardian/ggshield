from pathlib import Path

import pytest
from click.testing import CliRunner

from ggshield.cmd.main import cli
from tests.unit.conftest import assert_invoke_ok, my_vcr


@pytest.fixture(autouse=True)
def use_staging_env(monkeypatch):
    # The cassettes where recorded before the service was operational in production
    monkeypatch.setenv(
        "GITGUARDIAN_HMSL_URL", "https://hasmysecretleaked.staging.gitguardian.tech"
    )


@my_vcr.use_cassette
def test_hmsl_quota(cli_fs_runner: CliRunner, tmp_path: Path) -> None:
    """
    GIVEN our cli
    WHEN running the hmsl quota command
    THEN we should have a valid response
    """
    result = cli_fs_runner.invoke(cli, ["hmsl", "quota"])
    assert_invoke_ok(result)
    assert "Quota limit" in result.output
