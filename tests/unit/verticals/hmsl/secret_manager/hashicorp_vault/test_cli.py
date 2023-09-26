import subprocess
from typing import Generator
from unittest.mock import Mock, patch

import pytest

from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.cli import (
    get_vault_cli_token,
)
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.exceptions import (
    VaultCliTokenFetchingError,
)


@pytest.fixture()
def successful_vault_cli_call() -> Generator[Mock, None, None]:
    json_content = """
        {
            "data": {
                "id": "my_vault_token"
            }
        }
    """
    fake_response = subprocess.CompletedProcess(
        args="vault token lookup --format=json",
        returncode=0,
        stdout=json_content,
        stderr="",
    )

    with patch("subprocess.run", return_value=fake_response) as mock_func:
        yield mock_func


def test_get_vault_cli_token_successful(successful_vault_cli_call):
    """
    GIVEN a call to Vault cli to get the token
    WHEN Vault cli call is successful
    THEN the json response is parsed and the token is returned
    """
    ret = get_vault_cli_token()

    assert ret == "my_vault_token"
    successful_vault_cli_call.assert_called_once()


def test_get_vault_cli_token_vault_cli_parsing_error(successful_vault_cli_call):
    """
    GIVEN a call to Vault cli to get the token
    WHEN  Vault cli call is successful but there is a parsing error
    THEN VaultCliTokenFetchingError is raised with a proper error message
    """

    with patch(
        "ggshield.verticals.hmsl.secret_manager.hashicorp_vault.cli.json.loads",
        side_effect=RuntimeError(),
    ):
        with pytest.raises(
            VaultCliTokenFetchingError, match="error getting token from Vault CLI."
        ):
            ret = get_vault_cli_token()

            assert ret is None


def test_get_vault_cli_token_vault_cli_not_installed():
    """
    GIVEN a call to Vault cli to get the token
    WHEN the Vault CLI is not installed
    THEN VaultCliTokenFetchingError is raised with a proper error message
    """
    fake_exception = subprocess.CalledProcessError(
        returncode=127,  # return code for program not found
        cmd="vault token lookup --format=json",
        output="",
        stderr="vault: command not found",
    )

    with patch("subprocess.run", side_effect=fake_exception):
        with pytest.raises(
            VaultCliTokenFetchingError,
            match=r"Vault CLI not found. Are you sure it is installed and in your PATH\?",
        ):
            ret = get_vault_cli_token()

            assert ret is None


def test_get_vault_cli_token_non_zero_exit_code():
    """
    GIVEN a call to vault cli to get the token
    WHEN the vault CLI return with a non-zero exit code
    THEN VaultCliTokenFetchingError is raised with a proper error message
    """
    fake_exception = subprocess.CalledProcessError(
        returncode=2,  # return code for program not found
        cmd="vault token lookup --format=json",
        output="",
        stderr="error",
    )

    with patch("subprocess.run", side_effect=fake_exception):
        with pytest.raises(
            VaultCliTokenFetchingError,
            match=r"error when calling Vault CLI.",
        ):
            ret = get_vault_cli_token()

            assert ret is None
