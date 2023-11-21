import json
from unittest import mock

import jsonschema
import pytest
from pytest_voluptuous import S
from voluptuous.validators import All, Match

from ggshield.__main__ import cli
from tests.unit.conftest import assert_invoke_ok, my_vcr


def test_quota(cli_fs_runner, quota_json_schema):
    with my_vcr.use_cassette("quota"):
        cmd = ["quota", "--json"]
        result = cli_fs_runner.invoke(cli, cmd, color=False)
        assert_invoke_ok(result)

    dct = json.loads(result.output)
    jsonschema.validate(dct, quota_json_schema)

    assert dct["count"] + dct["remaining"] == dct["limit"]


def test_api_status(cli_fs_runner, api_status_json_schema):
    with my_vcr.use_cassette("test_health_check"):
        cmd = ["api-status", "--json"]
        result = cli_fs_runner.invoke(cli, cmd, color=False)
        assert_invoke_ok(result)

    dct = json.loads(result.output)
    jsonschema.validate(dct, api_status_json_schema)

    assert (
        S(
            All(
                {
                    "detail": "Valid API key.",
                    "status_code": 200,
                    "app_version": Match(r"v\d\.\d{1,3}\.\d{1,2}(-rc\.\d)?"),
                    "secrets_engine_version": Match(r"\d\.\d{1,3}\.\d"),
                }
            )
        )
        == dct
    )


@pytest.mark.parametrize("verify", [True, False])
def test_ssl_verify(cli_fs_runner, verify):
    cmd = ["api-status"] if verify else ["--allow-self-signed", "api-status"]

    with mock.patch("ggshield.core.client.GGClient") as client_mock:
        cli_fs_runner.invoke(cli, cmd)
        _, kwargs = client_mock.call_args
        assert kwargs["session"].verify == verify
