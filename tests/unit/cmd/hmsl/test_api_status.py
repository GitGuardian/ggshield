from pathlib import Path

from click.testing import CliRunner

from ggshield.__main__ import cli
from tests.unit.conftest import assert_invoke_ok, my_vcr


@my_vcr.use_cassette
def test_hmsl_api_status(cli_fs_runner: CliRunner, tmp_path: Path) -> None:
    """
    GIVEN our cli
    WHEN running the hmsl api-status command
    THEN we should have a valid response
    """
    result = cli_fs_runner.invoke(cli, ["hmsl", "api-status"])
    assert_invoke_ok(result)
    assert "healthy" in result.output
