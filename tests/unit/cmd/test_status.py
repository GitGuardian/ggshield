import json
from unittest import mock

import jsonschema
import pytest
import requests.exceptions
from pygitguardian.models import APITokensResponse, Detail, HealthCheckResponse
from pytest_voluptuous import S
from voluptuous.validators import All, In, Match

from ggshield.__main__ import cli
from ggshield.core.config.config import ConfigSource
from ggshield.core.errors import ExitCode
from ggshield.utils.os import cd
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok, my_vcr


def test_quota(cli_fs_runner, quota_json_schema):
    with my_vcr.use_cassette("quota"):
        cmd = ["quota", "--json"]
        cli_fs_runner.mix_stderr = False
        result = cli_fs_runner.invoke(cli, cmd, color=False)
        assert_invoke_ok(result)

    dct = json.loads(result.stdout)
    jsonschema.validate(dct, quota_json_schema)

    assert dct["count"] + dct["remaining"] == dct["limit"]


def test_api_status(cli_fs_runner, api_status_json_schema):
    with my_vcr.use_cassette("test_health_check"):
        cmd = ["api-status", "--json"]
        cli_fs_runner.mix_stderr = False
        result = cli_fs_runner.invoke(cli, cmd, color=False)
        assert_invoke_ok(result)

    dct = json.loads(result.stdout)
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
                    "token_scopes": ["scan"],
                    "workspace_id": 1,
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
@mock.patch(
    "pygitguardian.GGClient.api_tokens",
    return_value=APITokensResponse.from_dict(
        {
            "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
            "name": "test-token",
            "workspace_id": 1,
            "type": "personal_access_token",
            "status": "active",
            "created_at": "2023-01-01T00:00:00Z",
            "scopes": ["scan"],
        }
    ),
)
def test_api_status_sources(_, __, hs_mock, cli_fs_runner, tmp_path, monkeypatch):
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

        json_res = json.loads(result.stdout)
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


def test_api_status_shows_token_scopes(cli_fs_runner):
    """
    GIVEN a valid API token with scopes
    WHEN running api-status
    THEN the token scopes are displayed in the output
    """
    with my_vcr.use_cassette("test_health_check"):
        result = cli_fs_runner.invoke(cli, ["api-status"], color=False)
    assert_invoke_ok(result)
    assert "Token scopes:" in result.output
    assert "scan" in result.output


def test_api_status_shows_workspace_id(cli_fs_runner):
    """
    GIVEN a valid API token
    WHEN running api-status
    THEN the workspace id is displayed right below the API URL
    """
    with my_vcr.use_cassette("test_health_check"):
        result = cli_fs_runner.invoke(cli, ["api-status"], color=False)
    assert_invoke_ok(result)
    assert "Workspace ID: 1" in result.output

    lines = result.output.splitlines()
    api_url_index = next(
        i for i, line in enumerate(lines) if line.startswith("API URL:")
    )
    assert lines[api_url_index + 1].startswith("Workspace ID:")


@mock.patch(
    "pygitguardian.GGClient.api_tokens",
    return_value=Detail("Unauthorized", 401),
)
@mock.patch(
    "pygitguardian.GGClient.health_check",
    return_value=HealthCheckResponse(detail="Valid API key.", status_code=200),
)
def test_api_status_scopes_omitted_on_error(
    health_check_mock, api_tokens_mock, cli_fs_runner
):
    """
    GIVEN an api_tokens call that returns an error
    WHEN running api-status
    THEN the command succeeds and token scopes and workspace id are simply
        omitted from the output
    """
    result = cli_fs_runner.invoke(cli, ["api-status"], color=False)
    assert_invoke_ok(result)
    assert "Token scopes:" not in result.output
    assert "Workspace ID:" not in result.output


@mock.patch(
    "pygitguardian.GGClient.api_tokens",
    side_effect=requests.exceptions.JSONDecodeError(
        "Expecting value: line 1 column 1 (char 0)",
        "<!doctype html><html><body>GitGuardian</body></html>",
        0,
    ),
)
@mock.patch(
    "pygitguardian.GGClient.health_check",
    return_value=HealthCheckResponse(detail="Valid API key.", status_code=200),
)
def test_api_status_reports_clean_error_on_non_json_body(
    health_check_mock, api_tokens_mock, cli_fs_runner
):
    """
    GIVEN an instance URL that returns a non-JSON 2xx body (e.g. the SPA HTML),
        so api_tokens() would raise a raw JSONDecodeError
    WHEN running api-status
    THEN the command fails with a clean, actionable error mentioning the
        instance URL, not a raw JSONDecodeError traceback
    """
    result = cli_fs_runner.invoke(cli, ["api-status"], color=False)

    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    assert "instance URL" in result.output
    assert not isinstance(result.exception, requests.exceptions.JSONDecodeError)
