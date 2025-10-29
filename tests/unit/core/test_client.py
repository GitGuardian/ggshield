import os
from typing import Type
from unittest.mock import Mock, patch

import click
import pytest
import requests.exceptions
from pyfakefs.fake_filesystem import FakeFilesystem
from pygitguardian import GGClient
from pygitguardian.models import APITokensResponse, Detail, TokenScope

from ggshield.core.client import (
    check_client_api_key,
    create_client_from_config,
    create_session,
)
from ggshield.core.config import Config
from ggshield.core.errors import (
    APIKeyCheckError,
    MissingScopesError,
    ServiceUnavailableError,
    UnexpectedError,
    UnknownInstanceError,
)


@pytest.mark.parametrize(
    ("response", "error_class"),
    (
        (Detail("Guru Meditation", 500), ServiceUnavailableError),
        (Detail("Nobody here", 404), UnexpectedError),
        (Detail("Unauthorized", 401), APIKeyCheckError),
    ),
)
def test_check_client_api_key_error(response: Detail, error_class: Type[Exception]):
    """
    GIVEN a client returning an error when its healthcheck endpoint is called
    WHEN check_client_api_key() is called
    THEN it raises the appropriate exception
    """
    client_mock = Mock(spec=GGClient)
    client_mock.base_uri = "http://localhost"
    client_mock.read_metadata.return_value = response
    with pytest.raises(error_class):
        check_client_api_key(client_mock, set())


def test_check_client_api_key_network_error():
    """
    GIVEN a client with a wrong instance URL
    WHEN check_client_api_key() is called
    THEN it raises an UnexpectedError
    """
    client_mock = Mock()
    client_mock.health_check = Mock(side_effect=requests.exceptions.ConnectionError)
    client_mock.read_metadata = Mock(return_value=Detail("Not found", 404))
    with pytest.raises(UnexpectedError):
        check_client_api_key(client_mock, set())


def test_check_client_api_key_with_source_uuid_success():
    """
    GIVEN a client with valid API key and required scopes
    WHEN check_client_api_key() is called with scope scan:create-incidents
    THEN it succeeds without raising any exception
    """
    client_mock = Mock(spec=GGClient)
    client_mock.base_uri = "http://localhost"
    client_mock.read_metadata.return_value = None  # Success
    client_mock.api_tokens.return_value = APITokensResponse.from_dict(
        {
            "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
            "name": "test-name",
            "workspace_id": 1,
            "type": "personal_access_token",
            "status": "active",
            "created_at": "2023-01-01T00:00:00Z",
            "scopes": [TokenScope.SCAN_CREATE_INCIDENTS.value],
        }
    )

    # Should not raise any exception
    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})


def test_check_client_api_key_with_source_uuid_missing_scope():
    """
    GIVEN a client with valid API key but missing required scope
    WHEN check_client_api_key() is called with scope scan:create-incidents
    THEN it raises MissingScopesError
    """
    client_mock = Mock(spec=GGClient)
    client_mock.base_uri = "http://localhost"
    client_mock.read_metadata.return_value = None  # Success
    client_mock.api_tokens.return_value = APITokensResponse.from_dict(
        {
            "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
            "name": "test-name",
            "workspace_id": 1,
            "type": "personal_access_token",
            "status": "active",
            "created_at": "2023-01-01T00:00:00Z",
            "scopes": [
                TokenScope.INCIDENTS_READ.value
            ],  # Missing scan:create-incidents
        }
    )

    with pytest.raises(
        MissingScopesError,
        match="Token is missing the required scope scan:create-incidents",
    ):
        check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})


def test_check_client_api_key_with_source_uuid_api_tokens_error():
    """
    GIVEN a client with valid API key but api_tokens returns an error
    WHEN check_client_api_key() is called with scope scan:create-incidents
    THEN it raises UnexpectedError
    """
    client_mock = Mock(spec=GGClient)
    client_mock.base_uri = "http://localhost"
    client_mock.read_metadata.return_value = None  # Success
    client_mock.api_tokens.return_value = Detail("API tokens error", 500)

    with pytest.raises(UnexpectedError, match="API tokens error"):
        check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})


def test_check_client_api_key_with_source_uuid_unexpected_response():
    """
    GIVEN a client with valid API key but api_tokens returns unexpected response type
    WHEN check_client_api_key() is called with scope scan:create-incidents
    THEN it raises UnexpectedError
    """
    client_mock = Mock(spec=GGClient)
    client_mock.base_uri = "http://localhost"
    client_mock.read_metadata.return_value = None  # Success
    client_mock.api_tokens.return_value = "unexpected_response_type"

    with pytest.raises(UnexpectedError, match="Unexpected api_tokens response"):
        check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})


def test_check_client_api_key_without_source_uuid_no_token_check():
    """
    GIVEN a client with valid API key
    WHEN check_client_api_key() is called without required scopes
    THEN it doesn't call api_tokens
    """
    client_mock = Mock(spec=GGClient)
    client_mock.base_uri = "http://localhost"
    client_mock.read_metadata.return_value = None  # Success

    check_client_api_key(client_mock, set())

    # Should not call api_tokens
    client_mock.api_tokens.assert_not_called()


def test_check_client_api_key_unknown_scope():
    """
    GIVEN a client with valid API key and API returns unknown scopes
    WHEN check_client_api_key() is called with required scopes
    THEN it ignores unknown scopes and validates only the required ones
    """
    client_mock = Mock(spec=GGClient)
    client_mock.base_uri = "http://localhost"
    client_mock.read_metadata.return_value = None  # Success
    client_mock.api_tokens.return_value = APITokensResponse.from_dict(
        {
            "id": "5ddaad0c-5a0c-4674-beb5-1cd198d13360",
            "name": "test-name",
            "workspace_id": 1,
            "type": "personal_access_token",
            "status": "active",
            "created_at": "2023-01-01T00:00:00Z",
            "scopes": [TokenScope.SCAN_CREATE_INCIDENTS.value, "scope:unknown"],
        }
    )

    # Should not raise any exception
    check_client_api_key(client_mock, {TokenScope.SCAN_CREATE_INCIDENTS})


def test_retrieve_client_invalid_api_url():
    """
    GIVEN a GITGUARDIAN_API_URL missing its https scheme
    WHEN retrieve_client() is called
    THEN it raises a UsageError
    """
    url = "no-scheme.com"
    environ = os.environ.copy()
    environ.pop("GITGUARDIAN_INSTANCE", None)
    environ["GITGUARDIAN_API_URL"] = url

    with pytest.raises(
        click.UsageError,
        match=f"Invalid scheme for API URL '{url}', expected HTTPS",
    ):
        with patch.dict(os.environ, environ, clear=True):
            create_client_from_config(Config())


def test_retrieve_client_invalid_api_key():
    """
    GIVEN a GITGUARDIAN_API_KEY with a non-latin-1 character
    WHEN retrieve_client() is called
    THEN it raises a UnexpectedError
    """
    with pytest.raises(UnexpectedError, match="Invalid value for API Key"):
        with patch.dict(os.environ, {"GITGUARDIAN_API_KEY": "\u2023"}):
            create_client_from_config(Config())


def test_retrieve_client_blank_state(isolated_fs: FakeFilesystem):
    """
    GIVEN a blank state (no config, no environment variable)
    WHEN retrieve_client() is called
    THEN the exception message is user-friendly for new users
    """
    with pytest.raises(
        APIKeyCheckError,
        match="A GitGuardian API key is needed to use ggshield.",
    ):
        with patch.dict(os.environ, clear=True):
            create_client_from_config(Config())


def test_retrieve_client_unknown_custom_dashboard_url(isolated_fs: FakeFilesystem):
    """
    GIVEN an auth config telling the client to use a custom instance
    WHEN retrieve_client() is called
    AND the custom instance does not exist
    THEN the exception message mentions the instance name
    """
    with pytest.raises(
        UnknownInstanceError,
        match="Unknown instance: 'https://example.com'",
    ):
        with patch.dict(os.environ, clear=True):
            config = Config()
            config.cmdline_instance_name = "https://example.com"
            create_client_from_config(config)


def test_create_session_pool_configuration():
    """
    GIVEN create_session is called
    WHEN the session is created
    THEN the HTTPAdapter has the correct pool configuration
    """
    session = create_session()

    adapter = session.get_adapter("https://example.com")

    # Verify pool configuration by checking the init parameters
    assert getattr(adapter, "_pool_maxsize", None) == 100


@pytest.mark.parametrize("allow_self_signed", [True, False])
def test_create_session_with_self_signed_option(allow_self_signed: bool):
    """
    GIVEN create_session is called with allow_self_signed parameter
    WHEN the session is created
    THEN HTTPAdapter is mounted regardless of allow_self_signed value
    AND verify is set correctly
    """
    session = create_session(allow_self_signed=allow_self_signed)

    # Verify adapters are mounted
    assert "https://" in session.adapters

    # Verify SSL verification setting
    if allow_self_signed:
        assert session.verify is False
    else:
        assert session.verify is True
