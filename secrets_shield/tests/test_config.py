import os
import yaml
import click
import pytest
from mock import patch
from click.testing import CliRunner
from secrets_shield.config import load_config


@pytest.fixture(scope="session")
def cli_runner():
    os.environ["GITGUARDIAN_TOKEN"] = os.getenv("GITGUARDIAN_TOKEN", "1234567890")
    return CliRunner()


@pytest.fixture(scope="class")
def cli_fs_runner(cli_runner):
    with cli_runner.isolated_filesystem():
        yield cli_runner


class TestBlackListConfig:
    @patch("secrets_shield.config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("secrets_shield.config.CONFIG_GLOBAL", [""])
    def test_parsing_error(self, cli_fs_runner):
        os.system("echo '{}' > .gitguardian.yml".format("No a:\nyaml file.\n"))
        with pytest.raises(click.ClickException):
            assert load_config()

    @patch("secrets_shield.config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("secrets_shield.config.CONFIG_GLOBAL", [""])
    def test_simple_file_blacklist(self, cli_fs_runner):
        os.system(
            "echo '{}' > .gitguardian.yml".format(
                yaml.dump({"detectors": {"blacklist": ["google", "amazon"]}})
            )
        )

        config = load_config()
        assert config["blacklist"] == {"google", "amazon"}

    @patch("secrets_shield.config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("secrets_shield.config.CONFIG_GLOBAL", [".gitguardian.yaml"])
    def test_multiple_files_blacklist(self, cli_fs_runner):
        os.system(
            "echo '{}' > .gitguardian.yml".format(
                yaml.dump({"detectors": {"blacklist": ["google", "amazon"]}})
            )
        )

        os.system(
            "echo '{}' > .gitguardian.yaml".format(
                yaml.dump({"detectors": {"blacklist": ["microsoft"]}})
            )
        )

        config = load_config()
        assert config["blacklist"] == {"google", "amazon", "microsoft"}

    @patch("secrets_shield.config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("secrets_shield.config.CONFIG_GLOBAL", [".gitguardian.yaml"])
    def test_same_detectors_blacklist(self, cli_fs_runner):
        os.system(
            "echo '{}' > .gitguardian.yml".format(
                yaml.dump({"detectors": {"blacklist": ["google", "amazon"]}})
            )
        )

        os.system(
            "echo '{}' > .gitguardian.yaml".format(
                yaml.dump({"detectors": {"blacklist": ["google"]}})
            )
        )

        config = load_config()
        assert config["blacklist"] == {"google", "amazon"}
