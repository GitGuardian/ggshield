import os
import sys

import pytest
import yaml
from click.testing import CliRunner
from mock import patch

from ggshield.config import Config


@pytest.fixture(scope="session")
def cli_runner():
    os.environ["GITGUARDIAN_API_KEY"] = os.getenv("GITGUARDIAN_API_KEY", "1234567890")
    return CliRunner()


@pytest.fixture(scope="class")
def cli_fs_runner(cli_runner):
    with cli_runner.isolated_filesystem():
        yield cli_runner


@patch("ggshield.config.Config.CONFIG_LOCAL", [".gitguardian.yml"])
@patch("ggshield.config.Config.CONFIG_GLOBAL", [""])
def test_parsing_error(cli_fs_runner, capsys):
    with open(".gitguardian.yml", "w") as file:
        file.write("Not a:\nyaml file.\n")

    Config()
    out, err = capsys.readouterr()
    sys.stdout.write(out)
    sys.stderr.write(err)

    assert "Parsing error while opening .gitguardian.yml" in out


class TestConfig:
    @patch("ggshield.config.Config.CONFIG_LOCAL", [""])
    @patch("ggshield.config.Config.CONFIG_GLOBAL", [""])
    def test_defaults(self, cli_fs_runner):
        config = Config()
        assert config.verbose is False
        assert config.show_secrets is False
        assert len(config.matches_ignore) == 0
        assert len(config.paths_ignore) == 0

    @patch("ggshield.config.Config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("ggshield.config.Config.CONFIG_GLOBAL", [""])
    def test_display_options(self, cli_fs_runner):
        with open(".gitguardian.yml", "w") as file:
            file.write(yaml.dump({"verbose": True, "show_secrets": True}))

        config = Config()
        assert config.verbose is True
        assert config.show_secrets is True

    @patch("ggshield.config.Config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("ggshield.config.Config.CONFIG_GLOBAL", [""])
    def test_unknown_option(self, cli_fs_runner, capsys):
        with open(".gitguardian.yml", "w") as file:
            file.write(yaml.dump({"verbosity": True}))

        Config()
        captured = capsys.readouterr()
        assert "Unrecognized key in config" in captured.out

    @patch("ggshield.config.Config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("ggshield.config.Config.CONFIG_GLOBAL", [".gitguardian.yaml"])
    def test_display_options_inheritance(self, cli_fs_runner):
        with open(".gitguardian.yml", "w") as file:
            file.write(yaml.dump({"verbose": True, "show_secrets": False}))
        with open(".gitguardian.yaml", "w") as file:
            file.write(yaml.dump({"verbose": False, "show_secrets": True}))

        config = Config()
        assert config.verbose is True
        assert config.show_secrets is False

    @patch("ggshield.config.Config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("ggshield.config.Config.CONFIG_GLOBAL", [""])
    def test_exclude_regex(self, cli_fs_runner):
        with open(".gitguardian.yml", "w") as file:
            file.write(yaml.dump({"paths-ignore": ["/tests/"]}))

        config = Config()
        assert r"/tests/" in config.paths_ignore

    @patch("ggshield.config.Config.CONFIG_LOCAL", [".gitguardian.yml"])
    @patch("ggshield.config.Config.CONFIG_GLOBAL", [".gitguardian.yaml"])
    def test_accumulation_matches(self, cli_fs_runner):
        with open(".gitguardian.yml", "w") as file:
            file.write(yaml.dump({"matches_ignore": ["one", "two"]}))

        with open(".gitguardian.yaml", "w") as file:
            file.write(yaml.dump({"matches_ignore": ["three"]}))

        config = Config()
        assert config.matches_ignore == {"one", "two", "three"}
