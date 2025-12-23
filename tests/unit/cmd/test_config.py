import json
from datetime import datetime, timezone
from typing import Tuple

import jsonschema
import pytest
from pytest_voluptuous import S
from voluptuous import Any, In
from voluptuous.validators import All, Match

from ggshield.__main__ import cli
from ggshield.core.config import Config
from ggshield.core.config.user_config import UserConfig
from ggshield.core.config.utils import find_global_config_path
from ggshield.core.errors import ExitCode
from ggshield.utils.os import cd

from .utils import add_instance_config


DEFAULT_INSTANCE_URL = "https://dashboard.gitguardian.com"

EXPECTED_OUTPUT = """instance: None
default_token_lifetime: None

[https://dashboard.gitguardian.com]
default_token_lifetime: None
workspace_id: 1
url: https://dashboard.gitguardian.com
token: so** ***en
token_name: some token name
expiry: 2022-05-04T17:00:00Z

[https://some-gg-instance.com]
default_token_lifetime: None
workspace_id: 1
url: https://some-gg-instance.com
token: so** ***en
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


def _check_expected_output(output: str, expected_output: str):
    assert output == expected_output


class TestConfigList:

    @pytest.fixture
    def setup_configs(self, cli_fs_runner):
        """
        Set up multiple instance configs for tests.
        This fixture runs before each test method in this class.
        """
        some_date = datetime(2022, 5, 4, 17, 0, 0, 0, tzinfo=timezone.utc)

        add_instance_config(expiry_date=some_date)
        add_instance_config(
            instance_url="https://some-gg-instance.com",
            token_name="first token",
            expiry_date=some_date,
        )
        add_instance_config(
            instance_url="https://some-gg-instance.com",
            with_account=False,
            expiry_date=some_date,
        )

    def test_valid_list(self, cli_fs_runner, setup_configs):
        """
        GIVEN several config saved
        WHEN calling `ggshield config list` command
        THEN all configs should be listed with the correct format
        """
        exit_code, output = self.run_cmd(cli_fs_runner)

        assert exit_code == ExitCode.SUCCESS, output
        _check_expected_output(output, EXPECTED_OUTPUT)

    def test_list_json_output(
        self, cli_fs_runner, config_list_json_schema, setup_configs
    ):
        """
        GIVEN several config saved
        WHEN calling `ggshield config list` command
        THEN all configs should be listed with the correct format
        """
        exit_code_json, output_json = self.run_cmd(cli_fs_runner, json=True)
        assert exit_code_json == ExitCode.SUCCESS, output_json
        dct = json.loads(output_json)
        jsonschema.validate(dct, config_list_json_schema)
        assert (
            S(
                All(
                    {
                        "instances": [
                            {
                                "instance_name": str,
                                "default_token_lifetime": Any(None, str),
                                "workspace_id": In([1, "not set"]),
                                "url": Match(r"https://[^\s]+\.com"),
                                "token": str,
                                "token_name": str,
                                "expiry": Match(r"2022-05-04T17:00:00Z|not set"),
                            }
                        ],
                        "global_values": {
                            "instance": Any(None, str),
                            "default_token_lifetime": Any(None, str),
                        },
                    }
                )
            )
            == dct
        )

    @staticmethod
    def run_cmd(cli_fs_runner, json: bool = False) -> Tuple[bool, str]:
        cmd = ["config", "list", "--json"] if json else ["config", "list"]
        cli_fs_runner.mix_stderr = False if json else True
        result = cli_fs_runner.invoke(cli, cmd, color=False, catch_exceptions=False)
        return result.exit_code, result.output


class TestConfigSet:
    @pytest.mark.parametrize("value", [0, 365])
    def test_set_lifetime_default_config_value(self, value, cli_fs_runner):
        """
        GIVEN a saved protected config
        WHEN running the set command with a valid param and no instance specified
        THEN the default config specified field value be saved
        AND other instance configs must not be affected
        """
        unchanged_value = 42

        add_instance_config(default_token_lifetime=unchanged_value)
        exit_code, output = self.run_cmd(cli_fs_runner, value)

        config = Config()
        assert config.auth_config.default_token_lifetime == value, output
        assert (
            config.auth_config.get_instance(DEFAULT_INSTANCE_URL).default_token_lifetime
            == unchanged_value
        ), "The instance config should remain unchanged"

        assert exit_code == ExitCode.SUCCESS, output
        _check_expected_output(output, "")

    @pytest.mark.parametrize("value", [0, 365])
    def test_set_lifetime_instance_config_value(self, value, cli_fs_runner):
        """
        GIVEN a saved protected config
        WHEN running the set command with a valid param and the instance specified
        THEN the instance's specified field value be saved
        AND other configs must not be affected
        """
        unchanged_value = 4
        default_value = Config().auth_config.default_token_lifetime

        unrelated_instance = "https://some-unreleted-gg-instance.com"

        add_instance_config(default_token_lifetime=value)
        add_instance_config(unrelated_instance, default_token_lifetime=unchanged_value)

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

        assert exit_code == ExitCode.SUCCESS, output
        _check_expected_output(output, "")

    def test_set_invalid_field_name(self, cli_fs_runner):
        """
        GIVEN a saved protected config
        WHEN running the set command with an invalid field name
        THEN the command should exit with an error
        AND other configs must not be affected
        """
        default_value = Config().auth_config.default_token_lifetime

        exit_code, output = self.run_cmd(cli_fs_runner, 0, param="invalid_field_name")
        assert exit_code == ExitCode.USAGE_ERROR, output

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

        assert exit_code == ExitCode.USAGE_ERROR, output
        assert "Error: Invalid value: default_token_lifetime must be an int" in output

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

        assert exit_code == ExitCode.AUTHENTICATION_ERROR
        _check_expected_output(output, f"Error: Unknown instance: '{instance_url}'\n")

        config = Config()
        assert (
            config.auth_config.default_token_lifetime == default_value
        ), "The instance config should remain unchanged"

    def test_set_instance(self, cli_fs_runner, tmp_path):
        """
        GIVEN no global user config
        AND a local user config
        WHEN running the set command to set the instance
        THEN the instance is stored in the global user config
        AND the global user config contains only the instance
        """
        instance = "https://example.com"

        assert find_global_config_path() is None

        with cd(str(tmp_path)):
            # Create a local user config file, its content should not end up in the
            # global user config file
            config = Config()
            config.user_config.debug = True
            config.save()

            exit_code, output = self.run_cmd(cli_fs_runner, instance, param="instance")
            assert exit_code == ExitCode.SUCCESS, output

            # Explicitly load the global user config instead of using Config to ensure
            # the instance is stored where we expect it to be stored.
            config_path = find_global_config_path()
            config, _ = UserConfig.load(config_path)
            assert config.instance == instance
            # Check we did not save the local config to the global one
            assert (
                not config.debug
            ), "`config set` saved the local config to the global one"

    @staticmethod
    def run_cmd(
        cli_fs_runner, value, param="default_token_lifetime", instance_url=None
    ):
        cmd = ["config", "set", param, str(value)]
        if instance_url is not None:
            cmd.append("--instance=" + instance_url)
        result = cli_fs_runner.invoke(cli, cmd, color=False, catch_exceptions=False)
        return result.exit_code, result.output


class TestConfigUnset:
    def test_unset_lifetime_instance_config_value(self, cli_fs_runner):
        """
        GIVEN a saved protected config
        WHEN running the unset command with the instance specified
        THEN the specified field value must be erased from this config
        AND other configs must not be affected
        """
        unchanged_value = 42
        unset_value = 43
        default_value = Config().auth_config.default_token_lifetime

        unrelated_instance = "https://some-unreleted-gg-instance.com"

        add_instance_config(default_token_lifetime=unset_value)
        add_instance_config(unrelated_instance, default_token_lifetime=unchanged_value)

        exit_code, output = self.run_cmd(
            cli_fs_runner, instance_url=DEFAULT_INSTANCE_URL
        )

        config = Config()
        assert (
            config.auth_config.get_instance(DEFAULT_INSTANCE_URL).default_token_lifetime
            is None
        ), output
        assert (
            config.auth_config.get_instance(unrelated_instance).default_token_lifetime
            == unchanged_value
        ), "Unrelated instance config should remain unchanged"
        assert (
            config.auth_config.default_token_lifetime == default_value
        ), "The default auth config should remain unchanged"

        assert exit_code == ExitCode.SUCCESS, output
        _check_expected_output(output, "")

    def test_unset_lifetime_default_config_value(self, cli_fs_runner):
        """
        GIVEN a saved protected config
        WHEN running the unset command with no instance specified
        THEN the specified field value must be erased from the default config
        AND other configs must not be affected
        """
        unchanged_value = 42
        add_instance_config(default_token_lifetime=unchanged_value)
        exit_code, output = self.run_cmd(cli_fs_runner)

        config = Config()
        assert config.auth_config.default_token_lifetime is None, output
        assert (
            config.auth_config.get_instance(DEFAULT_INSTANCE_URL).default_token_lifetime
            == unchanged_value
        ), "Unrelated instance config should remain unchanged"

        assert exit_code == ExitCode.SUCCESS, output
        _check_expected_output(output, "")

    def test_unset_lifetime_all(self, cli_fs_runner):
        """
        GIVEN saved protected configs
        WHEN running the unset command with --all option
        THEN the specified field value must be erased from all configs
        (per instance and default)
        """
        second_instance = "https://some-gg-instance.com"
        add_instance_config(default_token_lifetime=30)
        add_instance_config(second_instance, default_token_lifetime=20)

        exit_code, output = self.run_cmd(cli_fs_runner, all_=True)

        config = Config()
        assert (
            config.auth_config.get_instance(DEFAULT_INSTANCE_URL).default_token_lifetime
            is None
        ), output
        assert (
            config.auth_config.get_instance(second_instance).default_token_lifetime
            is None
        ), output
        assert config.auth_config.default_token_lifetime is None, output

        assert exit_code == ExitCode.SUCCESS, output
        _check_expected_output(output, "")

    def test_unset_lifetime_invalid_instance(self, cli_fs_runner):
        """
        GIVEN -
        WHEN running the unset command with an unknown instance
        THEN the command should exit with and error
        AND no config must ne affected
        """
        instance_url = "https://some-invalid-gg-instance.com"

        default_value = Config().auth_config.default_token_lifetime

        exit_code, output = self.run_cmd(cli_fs_runner, instance_url=instance_url)

        assert exit_code == ExitCode.AUTHENTICATION_ERROR, output
        _check_expected_output(output, f"Error: Unknown instance: '{instance_url}'\n")

        config = Config()
        assert (
            config.auth_config.default_token_lifetime == default_value
        ), "The instance config should remain unchanged"

    def test_unset_instance(self, cli_fs_runner):
        """
        GIVEN a default instance previously set
        WHEN running `ggshield config unset instance`
        THEN the default instance is removed
        """
        # update global user config
        assert find_global_config_path() is None
        config_path = find_global_config_path(to_write=True)
        config = UserConfig()
        config.instance = "https://example.com"
        config.save(config_path)

        exit_code, output = self.run_cmd(cli_fs_runner, param="instance")

        assert exit_code == ExitCode.SUCCESS, output
        _check_expected_output(output, "")

        config, _ = UserConfig.load(config_path)
        assert config.instance is None

    @staticmethod
    def run_cmd(
        cli_fs_runner, param="default_token_lifetime", instance_url=None, all_=False
    ):
        cmd = ["config", "unset", param]
        if instance_url is not None:
            cmd.append("--instance=" + instance_url)
        elif all_:
            cmd.append("--all")
        result = cli_fs_runner.invoke(cli, cmd, color=False, catch_exceptions=False)
        return result.exit_code, result.output


class TestConfigGet:
    @pytest.mark.parametrize(
        ["default_value", "instance_value", "expected_value"],
        [
            (None, None, "not set"),
            (None, 42, "42"),
            (0, 42, "0"),
            (0, None, "0"),
            (365, 42, "365"),
        ],
    )
    def test_get_lifetime_default(
        self, default_value, instance_value, expected_value, cli_fs_runner
    ):
        """
        GIVEN saved protected configs
        WHEN running the get command without specifying an instance
        THEN it should display the value of the config in this order (if existing)
        AuthConfig > default config
        OR display "not set" if no value is found
        """
        # update default config
        config = Config()
        config.auth_config.default_token_lifetime = default_value
        config.save()

        add_instance_config(default_token_lifetime=instance_value)

        # add some noise
        unrelated_instance_url = "https://some-unrelated-gg-instance.com"
        add_instance_config(unrelated_instance_url, default_token_lifetime=43)

        exit_code, output = self.run_cmd(cli_fs_runner)

        _check_expected_output(output, f"default_token_lifetime: {expected_value}\n")
        assert exit_code == ExitCode.SUCCESS

    @pytest.mark.parametrize(
        ["default_value", "instance_value", "expected_value"],
        [
            (None, None, "not set"),
            (None, 1, "1"),
            (42, None, "not set"),
            (42, 0, "0"),
            (42, 365, "365"),
        ],
    )
    def test_get_lifetime_instance(
        self, default_value, instance_value, expected_value, cli_fs_runner
    ):
        """
        GIVEN saved protected configs
        WHEN running the get command with an instance specified
        THEN it should display the value for this specific config
        OR display "not set" if no value is found
        """
        instance_url = "https://some-gg-instance.com"
        unrelated_instance_url = "https://some-unrelated-gg-instance.com"

        # update default config
        config = Config()
        config.auth_config.default_token_lifetime = default_value
        config.save()

        add_instance_config(instance_url, default_token_lifetime=instance_value)
        add_instance_config(default_token_lifetime=43)
        add_instance_config(unrelated_instance_url, default_token_lifetime=44)

        exit_code, output = self.run_cmd(cli_fs_runner, instance_url=instance_url)

        expected_output = f"default_token_lifetime: {expected_value}\n"
        _check_expected_output(output, expected_output)
        assert exit_code == ExitCode.SUCCESS

    def test_unset_lifetime_invalid_instance(self, cli_fs_runner):
        """
        GIVEN -
        WHEN running the get command with an unknown instance
        THEN the command should exit with and error
        """
        instance_url = "https://some-invalid-gg-instance.com"
        exit_code, output = self.run_cmd(cli_fs_runner, instance_url=instance_url)

        assert exit_code == ExitCode.AUTHENTICATION_ERROR, output
        _check_expected_output(output, f"Error: Unknown instance: '{instance_url}'\n")

    def test_get_invalid_field_name(self, cli_fs_runner):
        """
        GIVEN _
        WHEN running the get command with an invalid field name
        THEN the command should exit with an error
        """
        exit_code, output = self.run_cmd(cli_fs_runner, param="invalid_field_name")
        assert exit_code == ExitCode.USAGE_ERROR, output

    @pytest.mark.parametrize(
        ["default_value", "expected_value"],
        [
            (None, "not set"),
            ("https://example.com", "https://example.com"),
        ],
    )
    def test_get_instance(self, default_value, expected_value, cli_fs_runner):
        """
        GIVEN a default instance previously set
        WHEN running `config get instance`
        THEN it should display the value for this specific config
        OR display "not set" if no value is found
        """

        # update global user config
        assert find_global_config_path() is None
        if default_value:
            config_path = find_global_config_path(to_write=True)
            config = UserConfig()
            config.instance = default_value
            config.save(config_path)

        exit_code, output = self.run_cmd(cli_fs_runner, param="instance")

        _check_expected_output(output, f"instance: {expected_value}\n")
        assert exit_code == ExitCode.SUCCESS

    @staticmethod
    def run_cmd(cli_fs_runner, param="default_token_lifetime", instance_url=None):
        cmd = ["config", "get", param]
        if instance_url is not None:
            cmd.append("--instance=" + instance_url)
        result = cli_fs_runner.invoke(cli, cmd, color=False, catch_exceptions=False)
        return result.exit_code, result.output
