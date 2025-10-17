import json
from unittest import mock

import jsonschema
import pytest
from pygitguardian.models import HealthCheckResponse
from pytest_voluptuous import S
from voluptuous.validators import All, In, Match

from ggshield.__main__ import cli
from ggshield.core.config.config import ConfigSource
from ggshield.utils.os import cd
from tests.unit.conftest import assert_invoke_ok, my_vcr


def test_quota(cli_fs_runner, quota_json_schema):
    with my_vcr.use_cassette("quota"):
        cmd = ["quota", "--json"]
        cli_fs_runner.mix_stderr = False
        result = cli_fs_runner.invoke(cli, cmd, color=False)
        assert_invoke_ok(result)

    dct = json.loads(result.output)
    jsonschema.validate(dct, quota_json_schema)

    assert dct["count"] + dct["remaining"] == dct["limit"]


def test_api_status(cli_fs_runner, api_status_json_schema):
    with my_vcr.use_cassette("test_health_check"):
        cmd = ["api-status", "--json"]
        cli_fs_runner.mix_stderr = False
        result = cli_fs_runner.invoke(cli, cmd, color=False)
        assert_invoke_ok(result)

    dct = json.loads(result.output)
    jsonschema.validate(dct, api_status_json_schema)

    assert (
        S(
            All(
                {
                    "detail": "Valid API key.",
                    "instance": Match(r"https://[^\s]+"),
                    "status_code": 200,
                    "app_version": Match(r"v\d\.\d{1,3}\.\d{1,2}(-rc\.\d)?"),
                    "secrets_engine_version": Match(r"\d\.\d{1,3}\.\d"),
                    "instance_source": In(x.name for x in ConfigSource),
                    "api_key_source": In(x.name for x in ConfigSource),
                }
            )
        )
        == dct
    )


@mock.patch(
    "ggshield.core.config.auth_config.AuthConfig.get_instance_token",
    return_value="token",
)
@mock.patch(
    "pygitguardian.GGClient.health_check",
    return_value=HealthCheckResponse(detail="", status_code=200),
)
def test_api_status_sources(_, hs_mock, cli_fs_runner, tmp_path, monkeypatch):
    """
    GIVEN an api_key and an instance configured anywhere
    WHEN running the api-status command
    THEN the correct api key and instance source are returned
    """
    (tmp_path / ".env").touch()

    monkeypatch.delenv("GITGUARDIAN_INSTANCE", raising=False)
    monkeypatch.delenv("GITGUARDIAN_API_URL", raising=False)

    def get_api_status(env, instance=None):
        with cd(tmp_path):
            cmd = ["api-status", "--json"]
            cli_fs_runner.mix_stderr = False
            if instance:
                cmd.extend(["--instance", instance])
            result = cli_fs_runner.invoke(cli, cmd, color=False, env=env)

        json_res = json.loads(result.output)
        return json_res["instance_source"], json_res["api_key_source"]

    env: dict[str, str | None] = {
        "GITGUARDIAN_INSTANCE": None,
        "GITGUARDIAN_URL": None,
        "GITGUARDIAN_API_KEY": None,
    }
    instance_source, api_key_source = get_api_status(env)
    assert instance_source == ConfigSource.DEFAULT.name
    assert api_key_source == ConfigSource.USER_CONFIG.name

    (tmp_path / ".gitguardian.yaml").write_text(
        "version: 2\ninstance: https://dashboard.gitguardian.com\n"
    )
    instance_source, api_key_source = get_api_status(env)
    assert instance_source == ConfigSource.USER_CONFIG.name
    assert api_key_source == ConfigSource.USER_CONFIG.name

    env["GITGUARDIAN_INSTANCE"] = "https://dashboard.gitguardian.com"
    env["GITGUARDIAN_API_KEY"] = "token"
    instance_source, api_key_source = get_api_status(env)
    assert instance_source == ConfigSource.ENV_VAR.name
    assert api_key_source == ConfigSource.ENV_VAR.name

    (tmp_path / ".env").write_text(
        "GITGUARDIAN_INSTANCE=https://dashboard.gitguardian.com\n"
        "GITGUARDIAN_API_KEY=token"
    )
    instance_source, api_key_source = get_api_status(env)
    assert instance_source == ConfigSource.DOTENV.name
    assert api_key_source == ConfigSource.DOTENV.name

    assert (
        get_api_status(env, instance="https://dashboard.gitguardian.com")[0]
        == ConfigSource.CMD_OPTION.name
    )


@pytest.mark.parametrize("verify", [True, False])
def test_ssl_verify(cli_fs_runner, verify):
    """
    GIVEN the --insecure flag
    WHEN running the api-status command
    THEN SSL verification is disabled
    """
    cmd = ["api-status"] if verify else ["--insecure", "api-status"]

    with mock.patch("ggshield.core.client.GGClient") as client_mock:
        cli_fs_runner.invoke(cli, cmd)
        _, kwargs = client_mock.call_args
        assert kwargs["session"].verify == verify


@pytest.mark.parametrize(
    "cmd",
    [
        ["api-status", "--allow-self-signed"],
        ["--allow-self-signed", "api-status"],
    ],
)
def test_allow_self_signed_backward_compatibility(cli_fs_runner, cmd):
    """
    GIVEN the deprecated --allow-self-signed flag
    WHEN it's placed before or after the subcommand
    THEN SSL verification is disabled in both cases (backward compatibility)
    """
    with mock.patch("ggshield.core.client.GGClient") as client_mock:
        cli_fs_runner.invoke(cli, cmd)
        _, kwargs = client_mock.call_args
        assert kwargs["session"].verify is False


@pytest.mark.parametrize("command", ["api-status", "quota"])
def test_instance_option(cli_fs_runner, command):
    """
    GIVEN an instance url
    WHEN running a command and passing the instance url as option
    THEN the call resulting from the command is made to the instance url
    """

    uri = "https://dashboard.my-instance.com"

    with mock.patch("ggshield.core.client.GGClient") as client_mock:
        cli_fs_runner.invoke(cli, [command, "--instance", uri])
        _, kwargs = client_mock.call_args
        assert kwargs["base_uri"] == "https://dashboard.my-instance.com/exposed"
