import json
from unittest import mock

import pytest
from pytest_voluptuous import Partial, S
from voluptuous.validators import All, Invalid, Match, Range

from ggshield.cmd.main import cli
from tests.conftest import assert_invoke_ok, my_vcr


def test_quota(cli_fs_runner):
    with my_vcr.use_cassette("quota"):
        cmd = ["quota", "--json"]
        result = cli_fs_runner.invoke(cli, cmd, color=False)
        assert_invoke_ok(result)

        def quota_values_must_match(output):
            if output["count"] + output["remaining"] != output["limit"]:
                raise Invalid("API calls count and remaining must sum to limit.")

        assert S(
            All(
                Partial(  # Partial validation because of the "since" key
                    {
                        "count": All(int, Range(min=0)),
                        "limit": All(int, Range(min=0)),
                        "remaining": All(int, Range(min=0)),
                    }
                ),
                quota_values_must_match,
            )
        ) == json.loads(result.output)


def test_api_status(cli_fs_runner):
    with my_vcr.use_cassette("test_health_check"):
        cmd = ["api-status", "--json"]
        result = cli_fs_runner.invoke(cli, cmd, color=False)
        assert_invoke_ok(result)

        assert S(
            All(
                Partial(  # Partial validation because of the "since" key
                    {
                        "detail": "Valid API key.",
                        "status_code": 200,
                        "app_version": Match(r"v\d\.\d{1,3}\.\d{1,2}(-rc\.\d)?"),
                        "secrets_engine_version": Match(r"\d\.\d{1,3}\.\d"),
                    }
                ),
            )
        ) == json.loads(result.output)


@pytest.mark.parametrize("verify", [True, False])
def test_ssl_verify(cli_fs_runner, verify):
    cmd = ["api-status"] if verify else ["--allow-self-signed", "api-status"]

    with mock.patch("ggshield.core.client.IaCGGClient") as client_mock:
        cli_fs_runner.invoke(cli, cmd)
        _, kwargs = client_mock.call_args
        assert kwargs["session"].verify == verify
