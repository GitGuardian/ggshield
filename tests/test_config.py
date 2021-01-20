import json
import os
import sys

import pytest
import yaml
from click.testing import CliRunner
from mock import patch

from ggshield.config import Cache, Config, replace_in_keys


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

    assert "Parsing error while reading .gitguardian.yml:" in out


class TestConfig:
    @patch("ggshield.config.Config.CONFIG_LOCAL", [""])
    @patch("ggshield.config.Config.CONFIG_GLOBAL", [""])
    def test_defaults(self, cli_fs_runner):
        config = Config()
        for attr in config.attributes:
            assert getattr(config, attr.name) == attr.default

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
            file.write(
                yaml.dump(
                    {
                        "verbose": True,
                        "show_secrets": False,
                        "api_url": "https://gitguardian.com",
                    }
                )
            )
        with open(".gitguardian.yaml", "w") as file:
            file.write(
                yaml.dump(
                    {
                        "verbose": False,
                        "show_secrets": True,
                        "api_url": "https://gitguardian.com/ex",
                    }
                )
            )

        config = Config()
        assert config.verbose is True
        assert config.show_secrets is False
        assert config.api_url == "https://gitguardian.com"

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
            file.write(
                yaml.dump(
                    {
                        "matches_ignore": [
                            {"name": "", "match": "one"},
                            {"name": "", "match": "two"},
                        ]
                    }
                )
            )

        with open(".gitguardian.yaml", "w") as file:
            file.write(yaml.dump({"matches_ignore": [{"name": "", "match": "three"}]}))
        config = Config()
        assert config.matches_ignore == [
            {"match": "three", "name": ""},
            {"match": "one", "name": ""},
            {"match": "two", "name": ""},
        ]


class TestUtils:
    def test_replace_in_keys(self):
        data = {"last-found-secrets": {"XXX"}}
        replace_in_keys(data, "-", "_")
        assert data == {"last_found_secrets": {"XXX"}}
        replace_in_keys(data, "_", "-")
        assert data == {"last-found-secrets": {"XXX"}}


class TestCache:
    def test_defaults(self, cli_fs_runner):
        cache = Cache()
        for attr in cache.attributes:
            assert getattr(cache, attr.name) == attr.default

    @patch("ggshield.config.Config.CONFIG_LOCAL", [".gitguardian.yml"])
    def test_load_cache_and_purge(self, cli_fs_runner):
        with open(".cache_ggshield", "w") as file:
            json.dump({"last_found_secrets": [{"name": "", "match": "XXX"}]}, file)
        cache = Cache()
        assert cache.last_found_secrets == [{"name": "", "match": "XXX"}]

        cache.purge()
        assert cache.last_found_secrets == []

    @patch("ggshield.config.Config.CONFIG_LOCAL", [".gitguardian.yml"])
    def test_load_invalid_cache(self, cli_fs_runner, capsys):
        with open(".cache_ggshield", "w") as file:
            json.dump({"invalid_option": True}, file)

        Cache()
        captured = capsys.readouterr()
        assert "Unrecognized key in cache" in captured.out

    @patch("ggshield.config.Config.CONFIG_LOCAL", [".gitguardian.yml"])
    def test_save_cache(self, cli_fs_runner):
        with open(".cache_ggshield", "w") as file:
            json.dump({}, file)
        cache = Cache()
        cache.update_cache(**{"last_found_secrets": {"XXX"}})
        cache.save()
        with open(".cache_ggshield", "r") as file:
            file_content = json.load(file)
            assert file_content == {"last_found_secrets": ["XXX"]}

    @patch("ggshield.config.Config.CONFIG_LOCAL", [".gitguardian.yml"])
    def test_save_cache_first_time(self, cli_fs_runner):
        os.remove(".cache_ggshield")
        cache = Cache()
        cache.save()
        assert os.path.isfile(".cache_ggshield") is True
