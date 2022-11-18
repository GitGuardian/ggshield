from pathlib import Path

from ggshield.cmd.main import cli
from tests.unit.conftest import assert_invoke_ok


def test_debug_option(cli_fs_runner):
    """
    GIVEN a directory with a configuration file
    WHEN ggshield is called with --debug
    THEN the log output contains the path to the configuration file
    """
    config_path = Path(".gitguardian.yaml")
    config_path.write_text("version: 2")

    cli_fs_runner.mix_stderr = False
    # Use a command which does not hit the network
    result = cli_fs_runner.invoke(cli, ["--debug", "config", "list"])
    assert_invoke_ok(result)
    assert ".gitguardian.yaml" in result.stderr
