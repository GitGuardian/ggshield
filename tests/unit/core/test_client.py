from typing import Type
from unittest.mock import Mock

import pytest
from pygitguardian.models import HealthCheckResponse

from ggshield.core.client import check_client_api_key
from ggshield.core.errors import APIKeyCheckError, UnexpectedError


@pytest.mark.parametrize(
    ("response", "error_class"),
    (
        (HealthCheckResponse("Guru Meditation", 500), UnexpectedError),
        (HealthCheckResponse("Unauthorized", 401), APIKeyCheckError),
    ),
)
def test_check_client_api_key_error(
    response: HealthCheckResponse, error_class: Type[Exception]
):
    """
    GIVEN a client returning an error when its healthcheck endpoint is called
    WHEN check_client_api_key() is called
    THEN it raises the appropriate exception
    """
    client_mock = Mock()
    client_mock.health_check.return_value = response
    with pytest.raises(error_class):
        check_client_api_key(client_mock)
