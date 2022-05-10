from datetime import datetime, timezone
from typing import Tuple

import pytest

from ggshield.cmd.main import cli
from ggshield.core.config import Config

from .utils import prepare_config


DEFAULT_INSTANCE_URL = "https://dashboard.gitguardian.com"

EXPECTED_OUTPUT = """[https://dashboard.gitguardian.com]
default_token_lifetime: None
workspace_id: 1
url: https://dashboard.gitguardian.com
token: some token
token_name: some token name
expiry: 2022-05-04T17:00:00Z

[https://some-gg-instance.com]
default_token_lifetime: None
workspace_id: 1
url: https://some-gg-instance.com
token: some token
token_name: first token
expiry: 2022-05-04T17:00:00Z

[https://some-gg-instance.com]
default_token_lifetime: None
workspace_id: not set
url: https://some-gg-instance.com
token: not set
token_name: not set
expiry: not set
"""


@pytest.fixture(autouse=True)
def tmp_config(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "ggshield.core.config.get_auth_config_dir", lambda: str(tmp_path)
    )


class TestAuthConfigList:
    def test_valid_list(self, cli_fs_runner):
        """
        GIVEN several auth config saved
        WHEN calling ggshield auth config list command
        THEN all config should be listed with the correct format
        """

        # May 4th
        some_date = datetime(2022, 5, 4, 17, 0, 0, 0, tzinfo=timezone.utc)

        prepare_config(expiry_date=some_date)
        prepare_config(
            instance_url="https://some-gg-instance.com",
            token="first_token",
            token_name="first token",
            expiry_date=some_date,
        )
        prepare_config(
            instance_url="https://some-gg-instance.com",
            with_account=False,
            expiry_date=some_date,
        )

        exit_code, output = self.run_cmd(cli_fs_runner)

        assert exit_code == 0, output
        assert output == EXPECTED_OUTPUT

    @staticmethod
    def run_cmd(cli_fs_runner) -> Tuple[bool, str]:
        cmd = ["config", "list"]
        result = cli_fs_runner.invoke(cli, cmd, color=False, catch_exceptions=False)
        return result.exit_code, result.output


class TestAuthConfigSet:
    @pytest.mark.parametrize("value", [0, 365])
    def test_set_lifetime_default_config_value(self, value, cli_fs_runner):
        """
        GIVEN a saved protected config
        WHEN running the set command with a valid param and no instance specified
        THEN the default config speficied field value be saved
        AND other instance configs must not be affected
        """
        unchanged_value = 42

        prepare_config(DEFAULT_INSTANCE_URL, default_token_lifetime=unchanged_value)
        exit_code, output = self.run_cmd(cli_fs_runner, value)

        config = Config()
        assert config.auth_config.default_token_lifetime == value, output
        assert (
            config.auth_config.get_instance(DEFAULT_INSTANCE_URL).default_token_lifetime
            == unchanged_value
        ), "The instance config should remain unchanged"

        assert exit_code == 0, output
        assert output == ""

    @pytest.mark.parametrize("value", [0, 365])
    def test_set_lifetime_instance_config_value(self, value, cli_fs_runner):
        """
        GIVEN a saved protected config
        WHEN running the set command with a valid param and the instance specified
        THEN the instance's speficied field value be saved
        AND other configs must not be affected
        """
        unchanged_value = 4
        default_value = Config().auth_config.default_token_lifetime

        unrelated_instance = "https://some-unreleted-gg-instance.com"

        prepare_config(DEFAULT_INSTANCE_URL, default_token_lifetime=value)
        prepare_config(unrelated_instance, default_token_lifetime=unchanged_value)

        exit_code, output = self.run_cmd(
            cli_fs_runner, value, instance_url=DEFAULT_INSTANCE_URL
        )

        config = Config()
        assert (
            config.auth_config.get_instance(DEFAULT_INSTANCE_URL).default_token_lifetime
            == value
        ), output
        assert (
            config.auth_config.get_instance(unrelated_instance).default_token_lifetime
            == unchanged_value
        ), "Unrelated instance config should remain unchanged"
        assert (
            config.auth_config.default_token_lifetime == default_value
        ), "The default auth config should remain unchanged"

        assert exit_code == 0, output
        assert output == ""

    def test_set_invalid_field_name(self, cli_fs_runner):
        """
        GIVEN a saved protected config
        WHEN running the set command with an invalid field name
        THEN the command should exit with an error
        AND other configs must not be affected
        """
        default_value = Config().auth_config.default_token_lifetime

        exit_code, output = self.run_cmd(cli_fs_runner, 0, param="invalid_field_name")

        assert exit_code == 2, output
        expected_output = (
            "Usage: cli config set [OPTIONS] {default_token_lifetime} VALUE\n"
            "Try 'cli config set -h' for help.\n\n"
            "Error: Invalid value for '{default_token_lifetime}': 'invalid_field_name' "
            "is not 'default_token_lifetime'.\n"
        )
        assert output == expected_output

        config = Config()
        assert (
            config.auth_config.default_token_lifetime == default_value
        ), "The instance config should remain unchanged"

    def test_set_lifetime_invalid_value(self, cli_fs_runner):
        """
        GIVEN a saved protected config
        WHEN running the set command with an invalid value
        THEN the command should exit with an error
        AND other configs must not be affected
        """
        default_value = Config().auth_config.default_token_lifetime

        exit_code, output = self.run_cmd(cli_fs_runner, "wrong_value")

        assert exit_code == 1, output
        assert output == "Error: default_token_lifetime must be an int\n"

        config = Config()
        assert (
            config.auth_config.default_token_lifetime == default_value
        ), "The instance config should remain unchanged"

    def test_set_lifetime_invalid_instance(self, cli_fs_runner):
        """
        GIVEN -
        WHEN running the set command for an unknown instance
        THEN the command should exit with an error
        AND other configs must not be affected
        """
        instance_url = "https://some-invalid-gg-instance.com"

        default_value = Config().auth_config.default_token_lifetime

        exit_code, output = self.run_cmd(cli_fs_runner, 0, instance_url=instance_url)

        assert exit_code == 1, output
        assert output == f"Error: Unknown instance: '{instance_url}'\n"

        config = Config()
        assert (
            config.auth_config.default_token_lifetime == default_value
        ), "The instance config should remain unchanged"

    @staticmethod
    def run_cmd(
        cli_fs_runner, value, param="default_token_lifetime", instance_url=None
    ):
        cmd = ["config", "set", param, str(value)]
        if instance_url is not None:
            cmd.append("--instance=" + instance_url)
        result = cli_fs_runner.invoke(cli, cmd, color=False, catch_exceptions=False)
        return result.exit_code, result.output
