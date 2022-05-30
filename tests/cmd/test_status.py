from unittest import mock

import pytest

from ggshield.cmd.main import cli
from tests.conftest import my_vcr


@pytest.mark.parametrize(
    "cassette, json_output",
    [
        ("quota", True),
        ("quota", False),
        ("quota_half_remaining", False),
        ("quota_low_remaining", False),
    ],
)
def test_quota(cassette, json_output, snapshot, cli_fs_runner):
    with my_vcr.use_cassette(cassette):
        cmd = ["quota", "--json"] if json_output else ["quota"]
        result = cli_fs_runner.invoke(cli, cmd, color=False)
        assert result.exit_code == 0
        snapshot.assert_match(result.output)


@pytest.mark.parametrize(
    "cassette, json_output",
    [
        ("test_health_check", True),
        ("test_health_check", False),
        ("test_health_check_error", False),
    ],
)
def test_api_status(cassette, json_output, snapshot, cli_fs_runner):
    with my_vcr.use_cassette(cassette):
        cmd = ["api-status", "--json"] if json_output else ["api-status"]
        result = cli_fs_runner.invoke(cli, cmd, color=False)
        assert result.exit_code == 0
        snapshot.assert_match(result.output)


@pytest.mark.parametrize("verify", [True, False])
def test_ssl_verify(cli_fs_runner, verify):
    cmd = ["api-status"] if verify else ["--allow-self-signed", "api-status"]

    with mock.patch("ggshield.core.client.IaCGGClient") as client_mock:
        cli_fs_runner.invoke(cli, cmd)
        _, kwargs = client_mock.call_args
        assert kwargs["session"].verify == verify
