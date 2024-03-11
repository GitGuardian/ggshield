import os
from typing import Type
from unittest.mock import Mock, patch

import click
import pytest
import requests.exceptions
from pygitguardian import GGClient
from pygitguardian.models import Detail

from ggshield.core.client import check_client_api_key, create_client_from_config
from ggshield.core.config import Config
from ggshield.core.errors import APIKeyCheckError, UnexpectedError, UnknownInstanceError


@pytest.mark.parametrize(
    ("response", "error_class"),
    (
        (Detail("Guru Meditation", 500), UnexpectedError),
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
        check_client_api_key(client_mock)


def test_check_client_api_key_network_error():
    """
    GIVEN a client with a wrong instance URL
    WHEN check_client_api_key() is called
    THEN it raises an UnexpectedError
    """
    client_mock = Mock()
    client_mock.health_check = Mock(side_effect=requests.exceptions.ConnectionError)
    with pytest.raises(UnexpectedError):
        check_client_api_key(client_mock)


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


def test_retrieve_client_blank_state(isolated_fs):
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


def test_retrieve_client_unknown_custom_dashboard_url(isolated_fs):
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
