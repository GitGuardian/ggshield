import os

import click
import pytest
import yaml
from click.testing import CliRunner
from mock import patch

from ggshield.config import load_config


@pytest.fixture(scope="session")
def cli_runner():
    os.environ["GITGUARDIAN_TOKEN"] = os.getenv("GITGUARDIAN_TOKEN", "1234567890")
    return CliRunner()


@pytest.fixture(scope="class")
def cli_fs_runner(cli_runner):
    with cli_runner.isolated_filesystem():
        yield cli_runner


@patch("ggshield.config.CONFIG_LOCAL", [".gitguardian.yml"])
@patch("ggshield.config.CONFIG_GLOBAL", [""])
def test_parsing_error(cli_fs_runner):
    with open(".gitguardian.yml", "w") as file:
        file.write("Not a:\nyaml file.\n")

    with pytest.raises(click.ClickException):
        assert load_config()


class TestBlackListConfig:
    @patch("ggshield.config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("ggshield.config.CONFIG_GLOBAL", [""])
    def test_simple_file_blacklist(self, cli_fs_runner):
        with open(".gitguardian.yml", "w") as file:
            file.write(yaml.dump({"detectors": {"blacklist": ["google", "amazon"]}}))

        config = load_config()
        assert config["blacklist"] == {"google", "amazon"}

    @patch("ggshield.config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("ggshield.config.CONFIG_GLOBAL", [".gitguardian.yaml"])
    def test_multiple_files_blacklist(self, cli_fs_runner):
        with open(".gitguardian.yml", "w") as file:
            file.write(yaml.dump({"detectors": {"blacklist": ["google", "amazon"]}}))

        with open(".gitguardian.yaml", "w") as file:
            file.write(yaml.dump({"detectors": {"blacklist": ["microsoft"]}}))

        config = load_config()
        assert config["blacklist"] == {"google", "amazon", "microsoft"}

    @patch("ggshield.config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("ggshield.config.CONFIG_GLOBAL", [".gitguardian.yaml"])
    def test_same_detectors_blacklist(self, cli_fs_runner):
        with open(".gitguardian.yml", "w") as file:
            file.write(yaml.dump({"detectors": {"blacklist": ["google", "amazon"]}}))

        with open(".gitguardian.yaml", "w") as file:
            file.write(yaml.dump({"detectors": {"blacklist": ["google"]}}))

        config = load_config()
        assert config["blacklist"] == {"google", "amazon"}


class TestIgnoreConfig:
    @patch("ggshield.config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("ggshield.config.CONFIG_GLOBAL", [""])
    def test_simple_file_ignore(self, cli_fs_runner):
        with open(".gitguardian.yml", "w") as file:
            file.write(
                yaml.dump({"ignore": {"filename": [".env"], "extension": ["exe"]}})
            )

        config = load_config()
        assert config["ignore"] == {"filename": {".env"}, "extension": {"exe"}}

    @patch("ggshield.config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("ggshield.config.CONFIG_GLOBAL", [".gitguardian.yaml"])
    def test_multiple_files_ignore(self, cli_fs_runner):
        with open(".gitguardian.yml", "w") as file:
            file.write(
                yaml.dump({"ignore": {"filename": [".env"], "extension": ["exe"]}})
            )

        with open(".gitguardian.yaml", "w") as file:
            file.write(
                yaml.dump({"ignore": {"filename": ["README.md"], "extension": ["png"]}})
            )

        config = load_config()
        assert config["ignore"] == {
            "filename": {".env", "README.md"},
            "extension": {"exe", "png"},
        }

    @patch("ggshield.config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("ggshield.config.CONFIG_GLOBAL", [".gitguardian.yaml"])
    def test_same_ignore(self, cli_fs_runner):
        with open(".gitguardian.yml", "w") as file:
            file.write(
                yaml.dump({"ignore": {"filename": [".env"], "extension": ["exe"]}})
            )

        with open(".gitguardian.yaml", "w") as file:
            file.write(
                yaml.dump({"ignore": {"filename": [".env"], "extension": ["png"]}})
            )

        config = load_config()
        assert config["ignore"] == {"filename": {".env"}, "extension": {"exe", "png"}}
