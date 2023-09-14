from urllib import parse as urlparse

import pytest

from ggshield.core.config import Config
from ggshield.verticals.auth import OAuthClient
from ggshield.verticals.auth.oauth import get_error_param


@pytest.mark.parametrize(
    ["url", "expected_error"],
    [
        ("http://localhost:3455", None),
        ("http://localhost:3455?", None),
        ("http://localhost:3455?auth=ggshield", None),
        ("http://localhost:3455?error=some+error", "some error"),
        ("http://localhost/?error=some+error", "some error"),
        ("http://localhost:3455/?auth=ggshield&error=some+error", "some error"),
    ],
)
def test_get_error_url_param(url, expected_error):
    """
    GIVEN a url
    WHEN calling get_error_param
    THEN it returns the value of the 'error' parameter if it exists else None
    """
    error = get_error_param(urlparse.urlparse(url))
    assert error == expected_error


@pytest.mark.parametrize(
    ["error_code", "expected_message"],
    [
        (
            "too_many_tokens",
            (
                "Maximum number of personal access tokens reached. "
                "Could not provision a new personal access token.\n"
                "Go to your workspace to manage your tokens: "
                "https://dashboard.gitguardian.com/api/personal-access-tokens"
            ),
        ),
        (
            "invalid_saml",
            "The given SSO URL is invalid.",
        ),
        (
            "invalid_scope",
            "The requested scopes are invalid.",
        ),
        (
            "invalid_error_code",
            "An unknown server error has occurred (error code: invalid_error_code).",
        ),
    ],
)
def test_get_error_message(error_code, expected_message):
    """
    GIVEN an OAuthClient instance and an error code
    WHEN calling OAuthClient.get_server_error with the error code
    THEN it should return the corresponding human readable message with formated urls
    """
    oauth_client = OAuthClient(Config(), "https://dashboard.gitguardian.com")
    error_message = oauth_client.get_server_error_message(error_code)
    assert error_message == expected_message
