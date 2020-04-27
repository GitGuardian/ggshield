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


class TestConfig:
    @patch("ggshield.config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("ggshield.config.CONFIG_GLOBAL", [""])
    def test_exclude_regex(self, cli_fs_runner):
        with open(".gitguardian.yml", "w") as file:
            file.write(yaml.dump({"exclude": r"/tests/"}))

        config = load_config()
        assert config["exclude"] == r"/tests/"

    @patch("ggshield.config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("ggshield.config.CONFIG_GLOBAL", [".gitguardian.yaml"])
    def test_accumulation_matches(self, cli_fs_runner):
        with open(".gitguardian.yml", "w") as file:
            file.write(yaml.dump({"ignored_matches": ["one", "two"]}))

        with open(".gitguardian.yaml", "w") as file:
            file.write(yaml.dump({"ignored_matches": ["three"]}))

        config = load_config()
        assert config["ignored_matches"] == {"one", "two", "three"}
