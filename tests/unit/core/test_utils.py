import os
import sys
from typing import AnyStr, Tuple
from unittest.mock import patch

import click
import pytest

from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.errors import APIKeyCheckError, UnexpectedError, UnknownInstanceError
from ggshield.core.scan.scan_context import parse_os_release


def test_retrieve_client_invalid_api_url():
    """
    GIVEN a GITGUARDIAN_API_URL missing its https scheme
    WHEN retrieve_client() is called
    THEN it raises a UsageError
    """
    url = "no-scheme.com"
    with pytest.raises(
        click.UsageError,
        match=f"Invalid scheme for API URL '{url}', expected HTTPS",
    ):
        with patch.dict(os.environ, {"GITGUARDIAN_API_URL": url}):
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


@pytest.mark.skipif(
    sys.platform.lower() != "linux", reason="This test is only relevant on Linux."
)
@pytest.mark.parametrize(
    "file_contents, file_permissions, expected_tuple",
    [
        ('ID="ubuntu"\nVERSION_ID=""22.04""', 777, ("ubuntu", "22.04")),
        ('ID="arch"', 777, ("arch", "unknown")),
        ("", 777, ("linux", "unknown")),
        ('ID="ubuntu"\nVERSION_ID="22.04"\n', 640, ("linux", "unknown")),
    ],
)
def test_parse_os_release(
    tmp_path,
    file_contents: AnyStr,
    file_permissions: int,
    expected_tuple: Tuple[str, str],
):
    file = tmp_path / "os-release"

    file.write_text(file_contents)
    file.chmod(file_permissions)
    assert parse_os_release(file) == expected_tuple
