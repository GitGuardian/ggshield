from typing import Any, Dict, List, Union

import pytest
from click.testing import CliRunner
from pytest_voluptuous import S

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from tests.unit.conftest import assert_invoke_exited_with, assert_invoke_ok, my_vcr
from tests.unit.request_mock import RequestMock, create_json_response


def test_honeytokens_create_no_arg(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN -
    WHEN running the honeytoken command with no argument
    THEN the return code is 2
    """

    result = cli_fs_runner.invoke(
        cli,
        [
            "honeytoken",
            "create",
        ],
    )
    assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)


@my_vcr.use_cassette("test_honeytoken_create_ok_no_name")
def test_honeytoken_create_ok_no_name(cli_fs_runner: CliRunner) -> None:
    """
    GIVEN -
    WHEN running the honeytoken command with no name
    THEN the return code is 0 and a name is generated
    """

    result = cli_fs_runner.invoke(
        cli,
        ["honeytoken", "create", "--description", "description", "--type", "AWS"],
    )
    assert_invoke_ok(result)


def test_honeytoken_create_ok(cli_fs_runner: CliRunner, monkeypatch) -> None:
    """
    GIVEN -
    WHEN running the honeytoken command with all needed arguments
    THEN the return code is 0
    """
    type_ = "AWS"
    name = "test_honey_token"
    description = "description"
    mock = RequestMock()
    monkeypatch.setattr("ggshield.core.client.Session.request", mock)

    def payload_checker(body: Union[List[str], Dict[str, Any]]) -> None:
        assert (
            S(
                {
                    "type": type_,
                    "description": description,
                    "name": name,
                }
            )
            == body
        )

    mock.add_POST(
        "/honeytokens",
        create_json_response(
            {
                "id": "858a3a76-f6f2-4c2e-b0bc-123456789012",
                "type": type_,
                "status": "active",
                "created_at": "2023-05-15T14:09:09.210845Z",
                "gitguardian_url": "https://dashboard.gitguardian.com/workspace/1/honeytokens/858a3a76-f6f2-4c2e-b0bc-123456789012",  # noqa: E501
                "revoked_at": None,
                "triggered_at": None,
                "open_events_count": 0,
                "creator_id": 265476,
                "creator_api_token_id": "8219e02d-f44c-4802-8418-210987654321",
                "revoker_id": None,
                "revoker_api_token_id": None,
                "token": {
                    "access_token_id": "ABCQFRJEIGOERJ5TRMP",
                    "secret_key": "9ImlMcdJrfjkriegj3454566C0YgLEgregerZEaa",  # ggignore
                },
                "tags": [],
                "name": name,
                "description": description,
            },
            201,
        ),
        json_checker=payload_checker,
    )

    result = cli_fs_runner.invoke(
        cli,
        [
            "honeytoken",
            "create",
            "--description",
            description,
            "--type",
            type_,
            "--name",
            name,
        ],
    )
    assert_invoke_ok(result)


@pytest.mark.parametrize(
    "subcommand, endpoint",
    [
        ("create", "/honeytokens"),
        ("create-with-context", "/honeytokens/with-context"),
    ],
)
@pytest.mark.parametrize(
    "response_message, expected_stdout",
    [
        (
            "Token is missing the following scope: honeytokens:read",
            "ggshield does not have permissions to create honeytokens",
        ),
        (
            "The account has an IP allowlist enabled, and your IP address "
            "is not permitted to access this resource.",
            "The account has an IP allowlist enabled, and your IP address "
            "is not permitted to access this resource.",
        ),
    ],
)
def test_honeytoken_create_error_403(
    cli_fs_runner: CliRunner,
    monkeypatch,
    subcommand: str,
    endpoint: str,
    response_message: str,
    expected_stdout: str,
) -> None:
    """
    GIVEN a command that will cause a 403 status code
    WHEN running the honeytoken command
    THEN the return code is UNEXPECTED_ERROR and the error message matches the expected message
    """

    mock = RequestMock()
    monkeypatch.setattr("ggshield.core.client.Session.request", mock)

    def payload_checker(body: Union[List[str], Dict[str, Any]]) -> None:
        assert body["type"] == "AWS"

    mock.add_POST(
        endpoint,
        create_json_response(
            {"detail": response_message},
            403,
        ),
        json_checker=payload_checker,
    )

    result = cli_fs_runner.invoke(
        cli,
        [
            "honeytoken",
            subcommand,
            "--type",
            "AWS",
        ],
    )
    assert_invoke_exited_with(result, ExitCode.UNEXPECTED_ERROR)
    mock.assert_all_requests_happened()
    assert expected_stdout in result.stdout
