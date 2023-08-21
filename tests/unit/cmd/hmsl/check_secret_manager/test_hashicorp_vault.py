from unittest.mock import patch

from ggshield.cmd.hmsl.check_secret_manager.hashicorp_vault import _get_vault_token


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
