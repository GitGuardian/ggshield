import sys

import pytest

from ggshield.core.config import Config
from ggshield.core.config.errors import ParseError
from tests.conftest import write_text, write_yaml


@pytest.mark.usefixtures("isolated_fs")
class TestUserConfig:
    def test_parsing_error(cli_fs_runner, capsys, local_config_path):
        write_text(local_config_path, "Not a:\nyaml file.\n")

        Config()
        out, err = capsys.readouterr()
        sys.stdout.write(out)
        sys.stderr.write(err)

        assert f"Parsing error while reading {local_config_path}:" in out

    def test_display_options(self, cli_fs_runner, local_config_path):
        write_yaml(local_config_path, {"verbose": True, "show_secrets": True})

        config = Config()
        assert config.verbose is True
        assert config.show_secrets is True

    def test_unknown_option(self, cli_fs_runner, capsys, local_config_path):
        write_yaml(local_config_path, {"verbosity": True})

        with pytest.raises(ParseError, match="Unknown field"):
            Config()

    def test_display_options_inheritance(
        self, cli_fs_runner, local_config_path, global_config_path
    ):
        write_yaml(
            local_config_path,
            {
                "verbose": True,
                "show_secrets": False,
                "api_url": "https://api.gitguardian.com",
            },
        )
        write_yaml(
            global_config_path,
            {
                "verbose": False,
                "show_secrets": True,
                "api_url": "https://api.gitguardian.com2",
            },
        )

        config = Config()
        assert config.verbose is True
        assert config.show_secrets is False
        assert config.api_url == "https://api.gitguardian.com"

    def test_exclude_regex(self, cli_fs_runner, local_config_path):
        write_yaml(local_config_path, {"paths-ignore": ["/tests/"]})

        config = Config()
        assert r"/tests/" in config.paths_ignore

    def test_accumulation_matches(
        self, cli_fs_runner, local_config_path, global_config_path
    ):
        write_yaml(
            local_config_path,
            {
                "matches_ignore": [
                    {"name": "", "match": "one"},
                    {"name": "", "match": "two"},
                ]
            },
        )
        write_yaml(
            global_config_path,
            {"matches_ignore": [{"name": "", "match": "three"}]},
        )
        config = Config()
        assert config.matches_ignore == [
            {"match": "three", "name": ""},
            {"match": "one", "name": ""},
            {"match": "two", "name": ""},
        ]
