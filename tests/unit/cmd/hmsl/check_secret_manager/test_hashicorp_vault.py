from unittest.mock import Mock, patch

import pytest

from ggshield.__main__ import cli
from ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault import (
    _get_vault_token,
    _split_vault_mount_and_path,
)
from ggshield.verticals.hmsl.collection import (
    NAMING_STRATEGIES,
    PreparedSecrets,
    SecretWithKey,
)
from ggshield.verticals.hmsl.secret_manager.hashicorp_vault.models import (
    VaultKvMount,
    VaultSecrets,
)


def test_get_vault_token_from_vault_cli(monkeypatch):
    """
    GIVEN the _get_vault_token method
    WHEN getting the token from the Vault CLI
    THEN the result of the get_vault_cli_token in the vertical is used, not the one
    from env.
    """
    monkeypatch.setenv("VAULT_TOKEN", "should_not_use_token_from_env")

    token_from_cli = "cli_token"

    with patch(
        "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.get_vault_cli_token",
        return_value=token_from_cli,
    ) as get_vault_cli_token_mock:
        returned_token = _get_vault_token(use_vault_cli_token=True)

        assert returned_token == token_from_cli
        get_vault_cli_token_mock.assert_called_once()


def test_get_vault_token_from_env(monkeypatch):
    """
    GIVEN the _get_vault_token method
    WHEN getting the token from the Vault CLI
    THEN the token from the env is used, not the one from Vault cli
    """
    token_from_env = "my_env_vault_token"
    monkeypatch.setenv("VAULT_TOKEN", token_from_env)

    with patch(
        "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.get_vault_cli_token",
        return_value="should_not_use_token_from_cli",
    ) as get_vault_cli_token_mock:
        returned_token = _get_vault_token(use_vault_cli_token=False)

        assert returned_token == token_from_env
        get_vault_cli_token_mock.assert_not_called()


@pytest.mark.parametrize(
    "input_str,expected_output",
    [
        ("dev/b2b", ("dev", "b2b")),
        ("/dev/b2b/", ("dev", "b2b")),
        ("/dev/b2c", ("dev", "b2c")),
        ("dev/b2c/", ("dev", "b2c")),
        ("prod/web/app/2", ("prod", "web/app/2")),
        ("/prod/web/app/2/", ("prod", "web/app/2")),
        ("/prod/web/app/2", ("prod", "web/app/2")),
        ("prod/web/app/2/", ("prod", "web/app/2")),
    ],
)
def test_split_vault_mount_and_path(input_str, expected_output):
    """
    GIVEN a path combining mount and path
    WHEN calling _split_vault_mount_and_path
    THEN the mount and path are splitted correctly
    """

    assert _split_vault_mount_and_path(input_str) == expected_output


@patch("ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.check_secrets")
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.prepare",
)
@patch("ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.collect_list")
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault._get_vault_token",
    return_value="vault_token",
)
@patch(
    "ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault.VaultAPIClient",
)
@pytest.mark.parametrize("use_cli_token", [True, False])
@pytest.mark.parametrize("recursive", [True, False])
@pytest.mark.parametrize("mount_not_found", [True, False])
@pytest.mark.parametrize("verbose", [True, False])
def test_check_hashicorp_vault_cmd(
    vault_api_client_cls_mock,
    get_vault_token_mock,
    collect_mock,
    prepare_mock,
    check_secrets_mock,
    cli_fs_runner,
    recursive,
    use_cli_token,
    mount_not_found,
    verbose,
):
    """
    GIVEN the hmsl check-secret-manager hashicorp-vault command
    WHEN calling the command with different arguments
    THEN the expected vertical calls are made to compute the result
    """
    args = [
        "hmsl",
        "check-secret-manager",
        "hashicorp-vault",
        "--url",
        "http://127.0.0.1:6789",
        "secret",
    ]
    if recursive:
        args.append("--recursive")
    if use_cli_token:
        args.append("--use-cli-token")
    if verbose:
        args.append("--verbose")

    vault_api_client_mock = Mock()
    vault_api_client_cls_mock.return_value = vault_api_client_mock
    vault_api_client_mock.get_kv_mounts.return_value = (
        [] if mount_not_found else [VaultKvMount(name="secret", version="2")]
    )
    returned_api_secrets = [
        ("DATABASE_PASSWORD", "postgres_password"),
        ("SECRET_KEY", "my_secret_key"),
    ]
    collect_mock.return_value = [
        SecretWithKey(key=key, value=value) for key, value in returned_api_secrets
    ]
    prepare_mock.return_value = PreparedSecrets(
        payload=set([key for key, _ in returned_api_secrets]),
        mapping={key: f"hash_{value}" for key, value in returned_api_secrets},
    )
    vault_api_client_mock.get_secrets.return_value = VaultSecrets(
        secrets=returned_api_secrets,
        not_fetched_paths=["super_secret_path", "prod_credentials"],
    )

    cmd_ret = cli_fs_runner.invoke(cli, args)

    # get_vault_token is called and the API client is initialized
    get_vault_token_mock.assert_called_once_with(use_cli_token)
    vault_api_client_cls_mock.assert_called_once_with(
        "http://127.0.0.1:6789", "vault_token"
    )

    # Get the KV mounts and return an error if not found, else continue
    vault_api_client_mock.get_kv_mounts.assert_called_once()
    if mount_not_found:
        assert cmd_ret.exit_code == 128
        assert (
            cmd_ret.output
            == "Error: mount secret not found. Make sure it exists and that your token has access to it.\n"
        )
        return

    # Secrets are fetched
    vault_api_client_mock.get_secrets.assert_called_once_with(
        VaultKvMount(name="secret", version="2"), "", recursive
    )

    # Collect, prepare and common check are called
    collect_mock.assert_called_once_with(returned_api_secrets)
    prepare_mock.assert_called_once_with(
        collect_mock.return_value, NAMING_STRATEGIES["key"], full_hashes=True
    )
    check_secrets_mock.assert_called_once()

    assert cmd_ret.exit_code == 0
    assert "Fetching secrets from Vault...\n" in cmd_ret.output
    assert (
        "Could not fetch 2 paths. Make sure your token has access to all the secrets in your vault.\n"
        in cmd_ret.output
    )
    assert "Got 2 secrets.\n" in cmd_ret.output
    if verbose:
        assert (
            """Error: > The following paths could not be fetched:
Error: - super_secret_path
Error: - prod_credentials
"""
            in cmd_ret.output
        )
