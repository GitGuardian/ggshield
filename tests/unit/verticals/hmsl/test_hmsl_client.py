from typing import List, Optional, Union
from unittest import mock

import pytest

from ggshield import __version__
from ggshield.verticals.hmsl import HMSLClient
from ggshield.verticals.hmsl.client import PREFIX_LENGTH
from ggshield.verticals.hmsl.crypto import hash_string


SAMPLE_QUERY = ["408a5b05c35bb4d230e31da1f9afa0e8881050cb72775e925d6bc7cb945b4f39"]
SAMPLE_RESPONSE = {
    "matches": [
        {
            "hint": "5de9f935ee515de855551e1786d71f1d7f4c3805083f57dc49863ad624f5ba42",
            "payload": (
                "gubW5fk1nZF8I4yGVMdcpeZv3CDg5lKE4LTeWDmjD3YkuaMx9c7/HuzIv8T3"
                "X2KXAcEWME+wQBiUP0WJQY6dEUNbcvyBpuxl+KGLj7KC3Dxlt8U+Frv4vDnFwWouN3c="
            ),
        },
        {
            "hint": "df096cd78ff6d840a21d95db852d69c3bb7710945123841fe0cfae88561a32be",
            "payload": (
                "sEdfOFMcwEmt2ZNwRL4nuoiTsnHbycdC/OOUPOM0ktZQhQQmG60+Js57T003"
                "SP6brRO4EZILO9cWJGAaCWiv21rAgwCt2r6IZn2KodRq0S4RWHajbphRgOvw3j6oPQ=="
            ),
        },
    ]
}


@pytest.fixture
def hashes():
    """Return example hashes to serve as payload."""
    return [hash_string(letter) for letter in "abcdefghijklmnopqrstuvwxyz"]


def get_hmsl_client(
    hmsl_command_path: Optional[str] = None,
    prefix_length: int = PREFIX_LENGTH,
    jwt: Union[str, None] = None,
):
    """Return a HMSL client."""
    return HMSLClient(
        "foo",
        hmsl_command_path or "ggshield hmsl check",
        jwt=jwt,
        prefix_length=prefix_length,
    )


def test_hmsl_client_check_prefixes(hashes: List[str]):
    """
    GIVEN a HMSL client
    WHEN a batch of hashes is audited
    THEN the query contains prefixes
    """
    hmsl_client = get_hmsl_client(prefix_length=6)
    expected_prefixes = {hash[:6] for hash in hashes[:5]}

    with mock.patch("requests.Session.post") as post:
        list(hmsl_client.check(hashes[:5]))
        url, kwargs = post.call_args
        assert url == ("foo/v1/prefixes",)
        assert (
            "prefixes" in kwargs["json"]
            and set(kwargs["json"]["prefixes"]) == expected_prefixes
        )


def test_hmsl_client_check_hashes(hashes):
    """
    GIVEN a HMSL client
    WHEN a batch of hashes is audited as full hashes
    THEN the query contains full hashes
    """
    hmsl_client = get_hmsl_client()

    with mock.patch("requests.Session.post") as post:
        list(hmsl_client.check(hashes + hashes, full_hashes=True))
        url, kwargs = post.call_args
        assert url == ("foo/v1/hashes",)
        assert "hashes" in kwargs["json"] and set(kwargs["json"]["hashes"]) == set(
            hashes
        )


def test_hmsl_client_jwt(hashes):
    """
    GIVEN a HMSL client
    WHEN a JWT is provided
    THEN the query contains it as an Bearer token
    """
    hmsl_client = get_hmsl_client(jwt="bar")

    with mock.patch("requests.Session.post") as post:
        list(hmsl_client.check([]))
        assert not post.called
        list(hmsl_client.check(hashes[:1]))
        _, kwargs = post.call_args
        assert ("Authorization", "Bearer bar") in kwargs["headers"].items()


def test_hmsl_client_decode_response():
    """
    GIVEN a HMSL client
    WHEN a response is received
    THEN the response is properly decrypted
    """
    hmsl_client = get_hmsl_client()

    with mock.patch(
        "ggshield.verticals.hmsl.HMSLClient._query", return_value=SAMPLE_RESPONSE
    ):
        response = list(hmsl_client.check(SAMPLE_QUERY, full_hashes=False))
    assert len(response) == 1
    secret = response[0]
    assert secret.count == 42
    assert "github.com" in secret.url


@pytest.mark.parametrize(
    "command, expected_header_value",
    [
        (
            "ggshield hmsl check-secret-manager hashicorp-vault",
            "hmsl_check-secret-manager_hashicorp-vault",
        ),
        ("ggshield hmsl check", "hmsl_check"),
    ],
)
def test_hmsl_common_headers(command, expected_header_value):
    """
    GIVEN the HMSLClient class
    WHEN creating a new client instance
    THEN the underlying requests session has the GGShield-HMSL-Command-Name header set correctly
    """

    hmsl_client = get_hmsl_client(command)

    assert (
        hmsl_client.session.headers["GGShield-HMSL-Command-Name"]
        == expected_header_value
    )
    assert hmsl_client.session.headers["User-Agent"] == f"GGShield {__version__}"
