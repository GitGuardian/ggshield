import contextlib
import io
from datetime import datetime, timezone
from typing import Optional

import pytest

from ggshield.core.config import Config
from ggshield.core.config.user_config import (
    CURRENT_CONFIG_VERSION,
    IaCConfig,
    IaCConfigIgnoredPath,
    IaCConfigIgnoredPolicy,
    SCAConfig,
    SCAConfigIgnoredVulnerability,
    UserConfig,
)
from ggshield.core.errors import ParseError, UnexpectedError
from ggshield.core.types import IgnoredMatch
from tests.unit.conftest import write_text, write_yaml


@pytest.mark.usefixtures("isolated_fs")
class TestUserConfig:
    def _assert_times(self, time1: Optional[datetime], time2: Optional[str]):
        if time1 is not None:
            assert time1 == datetime.strptime(
                str(time2), "%Y-%m-%d %H:%M:%S"
            ).astimezone(timezone.utc)

    def test_parsing_error(cli_fs_runner, local_config_path):
        write_text(local_config_path, "Not a:\nyaml file.\n")
        expected_output = f"{local_config_path} is not a valid YAML file:"
        with pytest.raises(ParseError, match=expected_output):
            Config()

    def test_display_options(self, local_config_path):
        write_yaml(local_config_path, {"verbose": True, "show_secrets": True})

        config = Config()
        assert config.user_config.verbose is True
        assert config.user_config.secret.show_secrets is True

    def test_display_options_inheritance(self, local_config_path, global_config_path):
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
        assert config.user_config.verbose is True
        assert config.user_config.secret.show_secrets is False
        assert config.api_url == "https://api.gitguardian.com"

    def test_exclude_regex(self, local_config_path):
        write_yaml(local_config_path, {"paths-ignore": ["/tests/"]})

        config = Config()
        assert r"/tests/" in config.user_config.secret.ignored_paths

    def test_accumulation_matches(self, local_config_path, global_config_path):
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
        assert config.user_config.secret.ignored_matches == [
            IgnoredMatch(match="three", name=""),
            IgnoredMatch(match="one", name=""),
            IgnoredMatch(match="two", name=""),
        ]

    def test_load_too_new_version(self, local_config_path):
        """
        GIVEN a config file whose format is too recent
        WHEN we try to load it
        THEN an exception is raised
        """
        write_yaml(local_config_path, {"version": CURRENT_CONFIG_VERSION + 1})

        with pytest.raises(UnexpectedError):
            UserConfig.load(local_config_path)

    def test_save_load_roundtrip(self):
        config_path = "config.yaml"
        config = UserConfig()
        config.exit_zero = True
        config.secret.show_secrets = True

        config.save(config_path)

        config2, _ = UserConfig.load(config_path)

        assert config.exit_zero == config2.exit_zero
        assert config.secret.show_secrets == config2.secret.show_secrets

    def test_load_v1(self):
        config_path = "config.yaml"
        write_yaml(
            config_path,
            {
                "exit-zero": True,
                "show-secrets": True,
                "banlisted-detectors": ["d1", "d2"],
                "matches-ignore": [
                    {
                        "name": "foo",
                        "match": "abcdef",
                    },
                    # A match using the old format: just a sha256
                    "1234abcd",
                ],
                "paths-ignore": ["/foo", "/bar"],
            },
        )

        config, _ = UserConfig.load(config_path)

        assert config.exit_zero
        assert config.secret.show_secrets
        assert config.secret.ignored_detectors == {"d1", "d2"}
        assert config.secret.ignored_matches == [
            IgnoredMatch(name="foo", match="abcdef"),
            IgnoredMatch(name="", match="1234abcd"),
        ]
        assert config.secret.ignored_paths == {"/foo", "/bar"}

    def test_load_mixed_versions(self, local_config_path, global_config_path):
        write_yaml(global_config_path, {"paths-ignore": ["v1path"]})

        write_yaml(
            local_config_path, {"version": 2, "secret": {"ignored_paths": ["v2path"]}}
        )

        config, _ = UserConfig.load()
        assert config.secret.ignored_paths == {"v1path", "v2path"}

    def test_load_ignored_matches_with_empty_names(self):
        config_path = "config.yaml"
        # Use write_text() here because write_yaml() cannot generate a key with a really
        # empty value, like we need for secret.ignored_matches[0].name
        write_text(
            config_path,
            """
            version: 2
            secret:
              ignored_matches:
                - name:
                  match: abcd
                - name: ""
                  match: dbca
            """,
        )
        config, _ = UserConfig.load(config_path)

        assert config.secret.ignored_matches == [
            IgnoredMatch(name="", match="abcd"),
            IgnoredMatch(name="", match="dbca"),
        ]

    @pytest.mark.parametrize(
        "paths",
        (
            ["mypath"],
            [{"path": "mypath"}],
            [{"path": "mypath"}, {"path": "mypath"}],
            [
                {
                    "path": "mypath",
                    "comment": "mycomment",
                    "until": "2050-01-01 00:00:00",
                }
            ],
            ["myfirstpath", {"path": "mysecondpath", "comment": "mycomment"}],
        ),
    )
    @pytest.mark.parametrize(
        "policies",
        (
            ["GG_IAC_0001"],
            [{"policy": "GG_IAC_0001"}],
            [{"policy": "GG_IAC_0001"}, {"policy": "GG_IAC_0001"}],
            [
                {
                    "policy": "GG_IAC_0001",
                    "comment": "mycomment",
                    "until": "2050-01-01 00:00:00",
                }
            ],
            ["GG_IAC_0001", {"policy": "GG_IAC_0002", "comment": "mycomment"}],
        ),
    )
    def test_iac_config(self, local_config_path, paths, policies):
        write_yaml(
            local_config_path,
            {
                "version": 2,
                "iac": {
                    "ignored_paths": paths,
                    "ignored_policies": policies,
                    "minimum_severity": "myseverity",
                },
            },
        )
        config = Config()
        iac_config = config.user_config.iac

        assert isinstance(iac_config, IaCConfig)
        for i, result in enumerate(iac_config.ignored_policies):
            expected = (
                IaCConfigIgnoredPolicy(policy=policies[i])
                if isinstance(policies[i], str)
                else IaCConfigIgnoredPolicy(**policies[i])
            )
            assert isinstance(result, IaCConfigIgnoredPolicy)
            assert result.policy == expected.policy
            assert result.comment == expected.comment
            self._assert_times(result.until, expected.until)
        for i, result in enumerate(iac_config.ignored_paths):
            expected = (
                IaCConfigIgnoredPath(path=paths[i])
                if isinstance(paths[i], str)
                else IaCConfigIgnoredPath(**paths[i])
            )
            assert isinstance(result, IaCConfigIgnoredPath)
            assert result.path == expected.path
            assert result.comment == expected.comment
            self._assert_times(result.until, expected.until)
        assert iac_config.minimum_severity == "myseverity"

    def test_iac_ignore_until(self, local_config_path):
        """
        GIVEN a local config file with iac configs
        WHEN setting an ignore param with a past datetime
        THEN it's ignored, and a warning is shown
        """
        write_yaml(
            local_config_path,
            {
                "version": 2,
                "iac": {
                    "ignored_paths": [
                        {
                            "path": "mypath1",
                            "until": "2010-05-01T00:00:00",
                        },
                        {
                            "path": "mypath2",
                            "until": "2050-05-01T00:00:00",
                        },
                        {"path": "mypath3"},
                    ],
                    "ignored_policies": [
                        {
                            "policy": "GG_IAC_0001",
                            "until": "2010-05-01T00:00:00",
                        },
                        {
                            "policy": "GG_IAC_0002",
                            "until": "2050-05-01T00:00:00",
                        },
                        {"policy": "GG_IAC_0003"},
                    ],
                },
            },
        )
        f = io.StringIO()
        with contextlib.redirect_stderr(f):
            config = Config()

        iac_config = config.user_config.iac
        assert isinstance(iac_config, IaCConfig)
        assert {ignored.path for ignored in iac_config.ignored_paths} == {
            "mypath2",
            "mypath3",
        }
        assert {ignored.policy for ignored in iac_config.ignored_policies} == {
            "GG_IAC_0002",
            "GG_IAC_0003",
        }

        assert "mypath1 has an expired 'until' date" in f.getvalue()
        assert "GG_IAC_0001 has an expired 'until' date" in f.getvalue()

    def test_iac_ignore_dates(self, local_config_path):
        """
        GIVEN a local config file with iac configs
        WHEN setting until dates in different formats
        THEN all given formats are accepted
        """
        write_yaml(
            local_config_path,
            {
                "version": 2,
                "iac": {
                    "ignored_paths": [
                        {
                            "path": "mypath1",
                            "until": "2050-05-01T00:00:01Z",
                        },
                        {
                            "path": "mypath2",
                            "until": "2050-05-01T00:00:00",
                        },
                        {
                            "path": "mypath3",
                            "until": "2050-05-01 00:00:00",
                        },
                        {
                            "path": "mypath4",
                            "until": "2050-05-01",
                        },
                    ],
                },
            },
        )
        config = Config()
        iac_config = config.user_config.iac
        assert isinstance(iac_config, IaCConfig)
        assert len(iac_config.ignored_paths) == 4

    def test_iac_config_bad_policy_id(self, local_config_path):
        write_yaml(
            local_config_path,
            {
                "version": 2,
                "iac": {
                    "ignored_paths": ["mypath"],
                    "ignored_policies": ["GG_ACI_0001"],
                    "minimum_severity": "myseverity",
                },
            },
        )
        with pytest.raises(ParseError):
            Config()

    def test_iac_config_options_inheritance(
        self, local_config_path, global_config_path
    ):
        write_yaml(
            global_config_path,
            {
                "version": 2,
                "iac": {
                    "ignored_paths": ["myglobalpath"],
                    "ignored_policies": ["GG_IAC_0001"],
                    "minimum_severity": "myglobalseverity",
                },
            },
        )
        write_yaml(
            local_config_path,
            {
                "version": 2,
                "iac": {
                    "ignored_paths": ["mypath"],
                    "ignored_policies": ["GG_IAC_0002"],
                    "minimum_severity": "myseverity",
                },
            },
        )
        config = Config()
        iac_config = config.user_config.iac
        assert isinstance(iac_config, IaCConfig)
        assert {ignored.path for ignored in iac_config.ignored_paths} == {
            "myglobalpath",
            "mypath",
        }
        assert {ignored.policy for ignored in iac_config.ignored_policies} == {
            "GG_IAC_0001",
            "GG_IAC_0002",
        }
        assert iac_config.minimum_severity == "myseverity"

    def test_sca_config(self, local_config_path):
        """
        GIVEN a local config file with sca configs
        WHEN deserializing it
        THEN we get the right values
        """
        write_yaml(
            local_config_path,
            {
                "version": 2,
                "sca": {
                    "ignored_paths": ["mypath"],
                    "minimum_severity": "myseverity",
                    "ignored_vulnerabilities": [
                        {
                            "identifier": "GHSA-aaaa-bbbb-cccc",
                            "path": "Pipfile",
                            "comment": "Not my prob",
                        }
                    ],
                },
            },
        )
        config = Config()
        sca_config = config.user_config.sca
        assert isinstance(sca_config, SCAConfig)
        assert sca_config.ignored_paths == {"mypath"}
        assert sca_config.minimum_severity == "myseverity"
        assert len(sca_config.ignored_vulnerabilities) == 1
        assert sca_config.ignored_vulnerabilities[0] == SCAConfigIgnoredVulnerability(
            identifier="GHSA-aaaa-bbbb-cccc",
            path="Pipfile",
            comment="Not my prob",
            until=None,
        )

    def test_sca_ignore_vuln_until(self, local_config_path):
        """
        GIVEN a local config file with sca configs
        WHEN setting an ignore vulnerability param with a past datetime
        THEN it's ignored
        """
        write_yaml(
            local_config_path,
            {
                "version": 2,
                "sca": {
                    "ignored_vulnerabilities": [
                        {
                            "identifier": "GHSA-aaaa-bbbb-cccc",
                            "path": "Pipfile",
                            "comment": "Not my prob",
                            "until": "2023-05-01T00:00:00",
                        }
                    ],
                },
            },
        )
        config = Config()
        sca_config = config.user_config.sca
        assert isinstance(sca_config, SCAConfig)
        assert len(sca_config.ignored_vulnerabilities) == 0

    def test_config_options_inheritance(self, local_config_path, global_config_path):
        """
        GIVEN two config files (global and local)
        WHEN deserializing them
        THEN the inheritance is respected
        """
        write_yaml(
            global_config_path,
            {
                "version": 2,
                "secret": {
                    "show_secrets": True,
                },
                "sca": {
                    "ignored_paths": ["myglobalpath"],
                    "minimum_severity": "myglobalseverity",
                },
            },
        )
        write_yaml(
            local_config_path,
            {
                "version": 2,
                "sca": {
                    "ignored_paths": ["mypath"],
                    "minimum_severity": "myseverity",
                },
            },
        )
        config = Config()

        # Checks the global config value for `show_secrets` is still there after loading
        # the local config, which does not contain this key.
        assert config.user_config.secret.show_secrets

        sca_config = config.user_config.sca
        assert isinstance(sca_config, SCAConfig)
        assert sca_config.ignored_paths == {"myglobalpath", "mypath"}
        assert sca_config.minimum_severity == "myseverity"

    def test_sca_config_invalid_identifier(self, local_config_path, capsys):
        """
        GIVEN a local config file with an invalid identifier in sca config
        WHEN deserializing it
        THEN we get the expected error
        """
        write_yaml(
            local_config_path,
            {
                "version": 2,
                "sca": {
                    "ignored_vulnerabilities": [
                        {
                            # Invalid id
                            "identifier": "ABCD-bbbb",
                            "path": "Pipfile",
                        }
                    ],
                },
            },
        )

        with pytest.raises(ParseError):
            UserConfig.load(local_config_path)

    def test_user_config_unknown_keys(self, local_config_path, capsys):
        """
        GIVEN a config containing unknown keys
        WHEN deserializing it
        THEN the keys are ignored and a warning is raised for config keys
        """
        write_yaml(
            local_config_path,
            {
                "version": 2,
                "root_unknown": "false key",
                "iac": {"ignored_paths": ["myglobalpath"], "iac_unknown": [""]},
                "secret": {
                    "secret_invalid_key": "invalid key",
                    "ignored_matches": [
                        {
                            "name": "",
                            "match": "one",
                            "match_invalid_key": "two",
                            "nested-hashed": "example",
                        },
                    ],
                },
                "hashed-key": "example",
            },
        )
        UserConfig.load(local_config_path)
        captured = capsys.readouterr()
        assert "Unrecognized key in config: root_unknown" in captured.err
        assert "Unrecognized key in config: iac_unknown" in captured.err
        assert "Unrecognized key in config: secret_invalid_key" in captured.err
        assert "Unrecognized key in config: match_invalid_key" in captured.err
        assert "Unrecognized key in config: hashed_key" in captured.err
        assert "Unrecognized key in config: nested_hashed" in captured.err

    def test_user_config_dash_keys(self, local_config_path, capsys):
        """
        GIVEN a config containing keys separated with dashes
        WHEN deserializing it
        THEN the keys are loaded and a warning is raised for config keys
        """
        write_yaml(
            local_config_path,
            {
                "version": 2,
                "iac": {
                    "ignored-paths": ["myglobalpath"],
                },
            },
        )
        cfg, _ = UserConfig.load(local_config_path)
        captured = capsys.readouterr()

        assert cfg.iac.ignored_paths[0].path == "myglobalpath"
        assert (
            f"{local_config_path}: Config key ignored-paths is deprecated, use ignored_paths instead."
            in captured.err
        )

    def test_can_load_ignored_known_secrets_from_root(self, local_config_path):
        """
        GIVEN a config file containing the `ignore_known_secrets` key in the root mapping
        WHEN deserializing it
        THEN UserConfig.secret.ignore_known_secrets has the correct value
        """
        write_yaml(
            local_config_path,
            {
                "version": 2,
                "ignore_known_secrets": True,
            },
        )
        config, _ = UserConfig.load(local_config_path)
        assert config.secret.ignore_known_secrets

    def test_can_load_ignored_known_secrets_from_secret(self, local_config_path):
        """
        GIVEN a config file containing the `ignore_known_secrets` key in the `secret` mapping
        WHEN deserializing it
        THEN UserConfig.secret.ignore_known_secrets has the correct value
        """
        write_yaml(
            local_config_path,
            {
                "version": 2,
                "secret": {
                    "ignore-known-secrets": True,
                },
            },
        )
        config, _ = UserConfig.load(local_config_path)
        assert config.secret.ignore_known_secrets

    def test_bad_local_config(self, local_config_path, global_config_path):
        """
        GIVEN a malformed .gitguardian.yaml, with a list of instance
        WHEN loading the user condiguration
        THEN an error is returned
        """
        write_yaml(global_config_path, {"instance": "https://test.gitguardian.com/"})
        write_yaml(
            local_config_path, {"instance": ["https://dashboard.gitguardian.com/"]}
        )
        with pytest.raises(UnexpectedError):
            UserConfig.load()
