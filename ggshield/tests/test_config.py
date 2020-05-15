import os
import sys

import pytest
import yaml
from click.testing import CliRunner
from mock import patch

from ggshield.config import Config


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
def test_parsing_error(cli_fs_runner, capsys):
    with open(".gitguardian.yml", "w") as file:
        file.write("Not a:\nyaml file.\n")

    Config()
    out, err = capsys.readouterr()
    sys.stdout.write(out)
    sys.stderr.write(err)

    assert "Parsing error while opening .gitguardian.yml" in out


class TestConfig:
    @patch("ggshield.config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("ggshield.config.CONFIG_GLOBAL", [""])
    def test_exclude_regex(self, cli_fs_runner):
        with open(".gitguardian.yml", "w") as file:
            file.write(yaml.dump({"paths-ignore": ["/tests/"]}))

        config = Config()
        assert r"/tests/" in config.paths_ignore

    @patch("ggshield.config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("ggshield.config.CONFIG_GLOBAL", [".gitguardian.yaml"])
    def test_accumulation_matches(self, cli_fs_runner):
        with open(".gitguardian.yml", "w") as file:
            file.write(yaml.dump({"matches_ignore": ["one", "two"]}))

        with open(".gitguardian.yaml", "w") as file:
            file.write(yaml.dump({"matches_ignore": ["three"]}))

        config = Config()
        assert config.matches_ignore == {"one", "two", "three"}
