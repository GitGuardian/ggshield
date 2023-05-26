from typing import Type
from unittest.mock import Mock

import pytest
import requests.exceptions
from pygitguardian import GGClient
from pygitguardian.models import Detail

from ggshield.core.client import check_client_api_key
from ggshield.core.errors import APIKeyCheckError, UnexpectedError


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
