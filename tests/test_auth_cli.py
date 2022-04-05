from unittest.mock import Mock

import pytest

from ggshield.cmd import cli
from ggshield.config import Config

from .conftest import my_vcr


@pytest.fixture(autouse=True)
def tmp_config(monkeypatch, tmp_path):
    monkeypatch.setattr("ggshield.config.get_auth_config_dir", lambda: str(tmp_path))


class TestAuthLoginToken:
    @pytest.mark.parametrize(
        "cassette, expect_success",
        [
            ("test_auth_login_token_invalid", False),
            ("test_auth_login_token_invalid_scope", False),
            ("test_auth_login_token_valid", True),
        ],
    )
    def test_auth_login_token(self, cli_fs_runner, cassette, expect_success):
        """
        GIVEN an API token, valid or not
        WHEN the auth login command is called with --method=token
        THEN the validity of the token should be checked, and if valid, the user should be logged in
        """
        token = "mysupertoken"
        instance = "https://dashboard.gitguardian.com"
        cmd = ["auth", "login", "--method=token", f"--instance={instance}"]

        with my_vcr.use_cassette(
            cassette,
            # Disable VCR's header filtering, which removes the token from the request.
            # We want to check that we're using the token given in the command line.
            filter_headers=[],
        ) as vcr:
            result = cli_fs_runner.invoke(cli, cmd, color=False, input=token + "\n")
            assert all(
                request.headers.get("Authorization") == f"Token {token}"
                for request in vcr.requests
            )

        config = Config()
        if expect_success:
            assert result.exit_code == 0, result.output
            assert instance in config.auth_config.instances
            assert config.auth_config.instances[instance].account.token == token
        else:
            assert result.exit_code != 0
            if cassette == "test_auth_login_token_invalid_scope":
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
