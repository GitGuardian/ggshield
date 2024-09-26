from pathlib import Path

import pytest

from ggshield.__main__ import cli
from tests.unit.conftest import assert_invoke_ok


@pytest.mark.parametrize("use_debug", [True, False])
def test_log_to_stderr_option(cli_fs_runner, use_debug: bool):
    """
    GIVEN a directory with a configuration file
    WHEN ggshield is called with --debug
    THEN the log output contains the path to the configuration file
    """
    config_path = Path(".gitguardian.yaml")
    config_path.write_text("version: 2")

    cli_fs_runner.mix_stderr = False
    # Use a command which does not hit the network
    args = ["--debug"] if use_debug else ["--log-file", "-"]
    result = cli_fs_runner.invoke(cli, args + ["config", "list"])
    assert_invoke_ok(result)
    assert ".gitguardian.yaml" in result.stderr


def test_log_file_option(tmp_path, cli_fs_runner):
    """
    GIVEN a directory with a configuration file
    WHEN ggshield is called with --log-file out.log
    THEN out.log contains the path to the configuration file
    """
    config_path = Path(".gitguardian.yaml")
    config_path.write_text("version: 2")

    log_path = tmp_path / "out.log"

    cli_fs_runner.mix_stderr = False
    # Use a command which does not hit the network
    result = cli_fs_runner.invoke(cli, ["--log-file", str(log_path), "config", "list"])
    assert_invoke_ok(result)
    assert ".gitguardian.yaml" in log_path.read_text()
