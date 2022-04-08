from typing import Any, Dict
from unittest.mock import Mock

import pytest

from ggshield.cmd import cli
from ggshield.config import Config


@pytest.fixture(autouse=True)
def tmp_config(monkeypatch, tmp_path):
    monkeypatch.setattr("ggshield.config.get_auth_config_dir", lambda: str(tmp_path))


class TestAuthLoginToken:
    VALID_TOKEN_PAYLOAD = {
        "type": "personal_access_token",
        "account_id": 17,
        "name": "key",
        "scope": ["scan"],
        "expire_at": None,
    }
    INVALID_TOKEN_PAYLOAD = {"detail": "Invalid API key."}
    VALID_TOKEN_INVALID_SCOPE_PAYLOAD = {
        "type": "personal_access_token",
        "account_id": 17,
        "name": "key",
        "scope": ["read:incident", "write:incident", "share:incident", "read:member"],
        "expire_at": None,
    }

    @staticmethod
    def mock_autho_login_request(
        monkeypatch, status_code: int, json: Dict[str, Any]
    ) -> None:
        monkeypatch.setattr(
            "ggshield.client.GGClient.get",
            Mock(
                return_value=Mock(
                    status_code=status_code,
                    ok=status_code < 400,
                    json=lambda: json,
                )
            ),
        )

    @pytest.mark.parametrize("test_case", ["valid", "invalid_scope", "invalid"])
    def test_auth_login_token(self, monkeypatch, cli_fs_runner, test_case):
        """
        GIVEN an API token, valid or not
        WHEN the auth login command is called with --method=token
        THEN the validity of the token should be checked, and if valid, the user should be logged in
        """
        token = "mysupertoken"
        instance = "https://dashboard.gitguardian.com"
        cmd = ["auth", "login", "--method=token", f"--instance={instance}"]

        if test_case == "valid":
            self.mock_autho_login_request(monkeypatch, 200, self.VALID_TOKEN_PAYLOAD)
        elif test_case == "invalid_scope":
            self.mock_autho_login_request(
                monkeypatch, 200, self.VALID_TOKEN_INVALID_SCOPE_PAYLOAD
            )
        elif test_case == "invalid":
            self.mock_autho_login_request(monkeypatch, 401, self.INVALID_TOKEN_PAYLOAD)

        result = cli_fs_runner.invoke(cli, cmd, color=False, input=token + "\n")

        config = Config()
        if test_case == "valid":
            assert result.exit_code == 0, result.output
            assert instance in config.auth_config.instances
            assert config.auth_config.instances[instance].account.token == token
        else:
            assert result.exit_code != 0
            if test_case == "invalid_scope":
                assert "This token does not have the scan scope." in result.output
            else:
                assert "Authentication failed with token." in result.output
            assert instance not in config.auth_config.instances

    def test_auth_login_token_default_instance(self, monkeypatch, cli_fs_runner):
        """
        GIVEN a valid API token
        WHEN the auth login command is called without --instance
        THEN the authentication is made against the default instance
        """
        config = Config()
        assert len(config.auth_config.instances) == 0

        self.mock_autho_login_request(monkeypatch, 200, self.VALID_TOKEN_PAYLOAD)

        cmd = ["auth", "login", "--method=token"]

        token = "mysupertoken"
        result = cli_fs_runner.invoke(cli, cmd, color=False, input=token + "\n")

        config = Config()
        assert result.exit_code == 0, result.output
        assert len(config.auth_config.instances) == 1
        assert config.auth_config.default_instance in config.auth_config.instances
        assert (
            config.auth_config.instances[
                config.auth_config.default_instance
            ].account.token
            == token
        )

    def test_auth_login_token_update_existing_config(self, monkeypatch, cli_fs_runner):
        """
        GIVEN some valid API tokens
        WHEN the auth login command is called with --method=token
        THEN the instance configuration is created if it doesn't exist, or updated otherwise
        """
        monkeypatch.setattr(
            "ggshield.client.GGClient.get",
            Mock(
                return_value=Mock(
                    ok=True,
                    json=lambda: {
                        "type": "personal_access_token",
                        "account_id": 17,
                        "name": "key",
                        "scope": ["scan"],
                        "expire_at": None,
                    },
                )
            ),
        )

        instance = "https://dashboard.gitguardian.com"
        cmd = ["auth", "login", "--method=token", f"--instance={instance}"]

        token = "myfirstsupertoken"
        result = cli_fs_runner.invoke(cli, cmd, color=False, input=token + "\n")

        config = Config()
        assert result.exit_code == 0, result.output
        assert config.auth_config.instances[instance].account.token == token

        token = "mysecondsupertoken"
        result = cli_fs_runner.invoke(cli, cmd, color=False, input=token + "\n")

        config = Config()
        assert result.exit_code == 0, result.output
        assert len(config.auth_config.instances) == 1
        assert config.auth_config.instances[instance].account.token == token

        second_instance_token = "mythirdsupertoken"
        second_instance = "https://dashboard.other.gitguardian.com"
        cmd = ["auth", "login", "--method=token", f"--instance={second_instance}"]
        result = cli_fs_runner.invoke(
            cli, cmd, color=False, input=second_instance_token + "\n"
        )

        config = Config()
        assert result.exit_code == 0, result.output
        assert len(config.auth_config.instances) == 2
        assert config.auth_config.instances[instance].account.token == token
        assert (
            config.auth_config.instances[second_instance].account.token
            == second_instance_token
        )
