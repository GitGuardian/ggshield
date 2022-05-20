from typing import Optional
from unittest.mock import Mock

import pytest
from requests.exceptions import ConnectionError

from ggshield.cmd.main import cli
from ggshield.core.config import Config

from ..utils import prepare_config


DEFAULT_INSTANCE_URL = "https://dashboard.gitguardian.com"


@pytest.fixture(autouse=True)
def tmp_config(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "ggshield.core.config.utils.get_auth_config_dir", lambda: str(tmp_path)
    )


class TestAuthLogout:
    def test_logout_no_account_config(self, cli_fs_runner):
        """
        GIVEN -
        WHEN using the logout command and no token is saved in the configuration
        THEN the command exits with an explanatory message
        """
        instance_url = "https://dashboard.gitguardian.com"
        prepare_config(with_account=False)
        exit_code, output = self.run_cmd(cli_fs_runner, instance_url)

        assert exit_code == 1, output
        assert output == (
            f"Error: No token found for instance {instance_url}\n"
            "First try to login by running:\n"
            "  ggshield auth login\n"
        )

    @pytest.mark.parametrize("instance_url", (None, "https://some-gg-instance.com"))
    @pytest.mark.parametrize("revoke", (True, False))
    def test_valid_logout(self, revoke, instance_url, monkeypatch, cli_fs_runner):
        """
        GIVEN a saved instance configuration
        WHEN running the logout command
        THEN the specified instance data is erased
        AND the request for revocation is made if no flag was included
        """
        unrelated_url = "https://some-unrelated-gg-instance.com"

        post_mock = Mock(return_value=Mock(status_code=204, ok=True))
        monkeypatch.setattr("ggshield.core.client.GGClient.post", post_mock)

        token_name = "My great token"
        prepare_config(instance_url=instance_url, token_name=token_name)

        # unrelated config that should remain unchanged
        prepare_config(instance_url=unrelated_url)

        exit_code, output = self.run_cmd(cli_fs_runner, instance_url, revoke=revoke)

        if revoke:
            post_mock.assert_called_once()
        else:
            post_mock.assert_not_called()

        config = Config()
        assert config.auth_config.get_instance(instance_url).account is None
        assert (
            config.auth_config.get_instance(unrelated_url).account is not None
        ), "the unrelated instance should not be affected."

        assert exit_code == 0, output
        instance_url = instance_url or "https://dashboard.gitguardian.com"

        expected_output = f"Successfully logged out for instance {instance_url}\n\n"

        if revoke:
            expected_output += (
                "Your personal access token has been revoked and removed "
                "from your configuration.\n"
            )
        else:
            expected_output += (
                "Your personal access token has been removed "
                "from your configuration.\n"
            )

        assert output == expected_output

    def test_logout_revoke_timeout(self, monkeypatch, cli_fs_runner):
        """
        GIVEN a saved instance configuration
        WHEN running the logout command (with implied token revokation)
        AND the revoke request gets a timeout
        THEN the config remains unchanged
        AND the command exits with an explanatory message
        """

        post_mock = Mock(side_effect=ConnectionError("Http max retry"))
        monkeypatch.setattr("ggshield.core.client.GGClient.post", post_mock)

        prepare_config()
        exit_code, output = self.run_cmd(cli_fs_runner)

        post_mock.assert_called_once()
        config = Config()
        assert config.auth_config.get_instance(DEFAULT_INSTANCE_URL).account is not None

        assert exit_code == 1, output
        assert output == (
            "Error: Could not connect to GitGuardian.\n"
            "Please check your internet connection and if the specified URL is correct.\n"
        )

    def test_logout_server_error(self, monkeypatch, cli_fs_runner):
        """
        GIVEN a saved instance configuration
        WHEN running the logout command (with implied token revokation)
        AND the revoke request gets a server error response
        THEN the config remains unchanged
        AND the command exits with an explanatory message
        """
        post_mock = Mock(return_value=Mock(status_code=500, ok=False))
        monkeypatch.setattr("ggshield.core.client.GGClient.post", post_mock)

        prepare_config()
        exit_code, output = self.run_cmd(cli_fs_runner)

        post_mock.assert_called_once()
        config = Config()
        assert config.auth_config.get_instance(DEFAULT_INSTANCE_URL).account is not None

        assert exit_code == 1, output
        assert output == (
            "Error: Could not perform the logout command "
            "because your token is already revoked or invalid.\n"
            "Please try with the following command:\n"
            "  ggshield auth logout --no-revoke\n"
        )

    def test_logout_all(self, monkeypatch, cli_fs_runner):
        """
        GIVEN several saved instances
        WHEN running the logout command with --all parameter
        THEN all tokens are revoked
        AND all account configs are deleted
        """
        post_mock = Mock(return_value=Mock(status_code=204, ok=True))
        monkeypatch.setattr("ggshield.core.client.GGClient.post", post_mock)

        for instance_url in [
            None,
            "https://some-gg-instance.com",
            "https://some-other-gg-instance.com",
        ]:
            prepare_config(instance_url)

        exit_code, output = self.run_cmd(cli_fs_runner, all_tokens=True)
        assert len(post_mock.call_args_list) == 3

        for instance in Config().auth_config.instances:
            assert instance.account is None, output

        assert exit_code == 0, output

    @staticmethod
    def run_cmd(
        cli_fs_runner,
        instance: Optional[str] = None,
        revoke: bool = True,
        all_tokens: bool = False,
    ) -> None:
        cmd = ["auth", "logout"]
        if instance is not None:
            cmd.append("--instance=" + instance)
        if not revoke:
            cmd.append("--no-revoke")
        if all_tokens:
            cmd.append("--all")
        result = cli_fs_runner.invoke(cli, cmd, color=False)
        return result.exit_code, result.output
