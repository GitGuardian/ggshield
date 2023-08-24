import os
import sys
from typing import AnyStr, Dict, Optional, Tuple
from unittest.mock import Mock, patch

import click
import pytest

from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.errors import APIKeyCheckError, UnexpectedError, UnknownInstanceError
from ggshield.core.scan.scan_context import parse_os_release
from ggshield.core.utils import load_dot_env
from ggshield.verticals.secret.repo import cd


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


@patch("ggshield.core.utils.load_dotenv")
@pytest.mark.parametrize(
    ["cwd", "env", "expected_dotenv_path"],
    [
        ("sub", {}, None),
        (".", {}, ".env"),
        (".", {"GITGUARDIAN_DONT_LOAD_ENV": "1"}, None),
        (".", {"GITGUARDIAN_DOTENV_PATH": ".custom-env"}, ".custom-env"),
        (".", {"GITGUARDIAN_DOTENV_PATH": ".does-not-exist"}, None),
    ],
)
def test_load_dot_env(
    load_dotenv_mock: Mock,
    monkeypatch,
    tmp_path,
    cwd: str,
    env: Dict[str, str],
    expected_dotenv_path: Optional[str],
):
    """
    GIVEN a file hierarchy like this:
    /sub/
    /.env
    /.custom-env
    AND environment variables set according to `env`
    AND the current working directory being `/sub/`
    WHEN load_dot_env() is called
    THEN the appropriate environment file is loaded
    """
    (tmp_path / "sub").mkdir()
    (tmp_path / ".env").touch()
    (tmp_path / ".custom-env").touch()

    if env:
        for key, value in env.items():
            monkeypatch.setenv(key, value)

    with cd(str(tmp_path / cwd)):
        load_dot_env()

        if expected_dotenv_path:
            expected_dotenv_path = tmp_path / expected_dotenv_path
            load_dotenv_mock.assert_called_once_with(
                str(expected_dotenv_path), override=True
            )
        else:
            load_dotenv_mock.assert_not_called()


@patch("ggshield.core.utils.get_git_root")
@patch("ggshield.core.utils.is_git_dir")
@patch("ggshield.core.utils.load_dotenv")
def test_load_dot_env_loads_git_root_env(
    load_dotenv_mock: Mock, is_git_dir_mock, get_git_root_mock, tmp_path
):
    """
    GIVEN a git repository checkout with this file hierarchy:
    /sub1/sub2
    /sub1/.env
    /.env
    AND the current working directory being `/sub1/sub2`
    WHEN load_dot_env() is called
    THEN the .env file at the root of the git repository is loaded
    """
    is_git_dir_mock.return_value = True
    get_git_root_mock.return_value = str(tmp_path)

    sub1_sub2_dir = tmp_path / "sub1" / "sub2"
    git_root_dotenv = tmp_path / ".env"

    sub1_sub2_dir.mkdir(parents=True)
    (tmp_path / "sub1" / ".env").touch()
    git_root_dotenv.touch()

    with cd(str(sub1_sub2_dir)):
        load_dot_env()
        load_dotenv_mock.assert_called_once_with(str(git_root_dotenv), override=True)


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
