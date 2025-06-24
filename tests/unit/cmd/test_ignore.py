import os
import tempfile
from unittest.mock import Mock, patch

from pygitguardian.models import Match, PolicyBreak

from ggshield.__main__ import cli
from ggshield.cmd.secret.ignore import ignore_last_found
from ggshield.core.cache import Cache
from ggshield.core.config import Config
from ggshield.core.errors import ExitCode
from ggshield.core.filter import get_ignore_sha
from ggshield.core.scan import Commit, ScanContext, ScanMode
from ggshield.core.types import IgnoredMatch
from ggshield.verticals.secret import SecretScanner
from tests.unit.conftest import (
    _MULTIPLE_SECRETS_PATCH,
    assert_invoke_exited_with,
    assert_invoke_ok,
    my_vcr,
)


DOT_GITGUARDIAN_YAML = os.path.join(tempfile.gettempdir(), ".gitguardian.yml")

FOUND_SECRETS = [
    IgnoredMatch(
        name="MySQL Assignment - test.txt",
        match="41b8889e5e794b21cb1349d8eef1815960bf5257330fd40243a4895f26c2b5c8",
    )
]


def compare_matches_ignore(match):
    return (match.name, match.match) if isinstance(match, IgnoredMatch) else (match,)


def test_ignore_sha(cli_fs_runner):
    """
    GIVEN an empty cache and an empty config ignored_matches section
    WHEN I ignore a secret sha
    THEN the ignore secret is added to the config and saved
    """
    ignored_match = IgnoredMatch(
        name="test_name",
        match="41b8889e5e794b21cb1349d8eef1815960bf5257330fd40243a4895f26c2b5c8",
    )
    config = Config()

    with patch("ggshield.cmd.utils.context_obj.ContextObj.get") as mock_get_ctx:
        mock_get_ctx.return_value.config = config

        cmd = ["secret", "ignore", ignored_match.match, "--name", ignored_match.name]
        result = cli_fs_runner.invoke(cli, cmd, color=False, catch_exceptions=False)

        assert_invoke_ok(result)
        assert config.user_config.secret.ignored_matches == [ignored_match]


def test_error_sha_last_found(cli_fs_runner):
    """
    GIVEN any config and cache
    WHEN I run the command with invalid arguments
    THEN an error should be raised
    """

    cmd = ["secret", "ignore", "some_secret_sha", "--last-found"]
    result = cli_fs_runner.invoke(cli, cmd, color=False, catch_exceptions=False)

    assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
    assert (
        "Option `--last-found` cannot be used with `SECRET_SHA` or `--name`."
        in result.output
    )


def test_error_ignore_sha_no_name(cli_fs_runner):
    """
    GIVEN any config and cache
    WHEN I run the command with a secret sha but no name
    THEN an error should be raised
    """

    cmd = ["secret", "ignore", "some_secret_sha"]
    result = cli_fs_runner.invoke(cli, cmd, color=False, catch_exceptions=False)

    assert_invoke_exited_with(result, ExitCode.USAGE_ERROR)
    assert "Option `--name` is required when ignoring a secret." in result.output


def test_cache_catches_last_found_secrets(client, isolated_fs):
    """
    GIVEN an empty cache and an empty config ignored_matches section
    WHEN I run a scan with multiple secrets
    THEN cache last_found_secrets is updated with these secrets and saved
    """
    commit = Commit.from_patch(_MULTIPLE_SECRETS_PATCH)
    config = Config()
    cache = Cache()
    cache.purge()
    assert cache.last_found_secrets == list()

    with my_vcr.use_cassette("multiple_secrets"):
        scanner = SecretScanner(
            client=client,
            cache=cache,
            scan_context=ScanContext(
                scan_mode=ScanMode.COMMIT_RANGE,
                command_path="external",
            ),
            secret_config=config.user_config.secret,
        )
        scanner.scan(commit.get_files(), scanner_ui=Mock())
    assert config.user_config.secret.ignored_matches == list()

    cache_found_secrets = sorted(cache.last_found_secrets, key=compare_matches_ignore)
    found_secrets = sorted(FOUND_SECRETS, key=compare_matches_ignore)

    assert [found_secret.match for found_secret in cache_found_secrets] == [
        found_secret.match for found_secret in found_secrets
    ]
    ignore_last_found(config, cache)
    for ignore in config.user_config.secret.ignored_matches:
        assert "test.txt" in ignore.name
    cache.load_cache()


def test_cache_catches_nothing(client, isolated_fs):
    """
    GIVEN a cache of last found secrets same as config ignored_matches
    WHEN I run a scan (therefore finding no secret)
    THEN config matches is unchanged and cache is empty
    """
    commit = Commit.from_patch(_MULTIPLE_SECRETS_PATCH)
    config = Config()
    config.user_config.secret.ignored_matches = FOUND_SECRETS
    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS

    with my_vcr.use_cassette("multiple_secrets"):
        scanner = SecretScanner(
            client=client,
            cache=cache,
            scan_context=ScanContext(
                scan_mode=ScanMode.COMMIT_RANGE,
                command_path="external",
            ),
            secret_config=config.user_config.secret,
        )
        results = scanner.scan(commit.get_files(), scanner_ui=Mock())

        assert sum(len(result.secrets) for result in results.results) == 0
        assert config.user_config.secret.ignored_matches == FOUND_SECRETS
        assert cache.last_found_secrets == []


def test_ignore_last_found(client, isolated_fs):
    """
    GIVEN a cache of last found secrets not empty
    WHEN I run a ignore last found command
    THEN config ignored_matches is updated accordingly
    """
    config = Config()

    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS
    ignore_last_found(config, cache)

    matches_ignore = sorted(
        config.user_config.secret.ignored_matches, key=compare_matches_ignore
    )

    found_secrets = sorted(FOUND_SECRETS, key=compare_matches_ignore)

    assert matches_ignore == found_secrets
    assert cache.last_found_secrets == FOUND_SECRETS


def test_ignore_last_found_with_manually_added_secrets(client, isolated_fs):
    """
    GIVEN a cache containing part of config ignored_matches secrets
    WHEN I run ignore command
    THEN only new discovered secrets are added to the config
    """
    manually_added_secret = (
        "41b8889e5e794b21cb1349d8eef1815960bf5257330fd40243a4895f26c2b5c8"
    )
    config = Config()
    config.user_config.secret.ignored_matches = [
        IgnoredMatch(name="", match=manually_added_secret)
    ]
    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS

    ignore_last_found(config, cache)

    matches_ignore = sorted(
        config.user_config.secret.ignored_matches, key=compare_matches_ignore
    )

    found_secrets = sorted(FOUND_SECRETS, key=compare_matches_ignore)
    assert matches_ignore == found_secrets


def test_do_not_duplicate_last_found_secrets(client, isolated_fs):
    """
    GIVEN 2 policy breaks on different files with the same ignore sha
    WHEN add_found_policy_break is called
    THEN only one element should be added
    """
    policy_break = PolicyBreak(
        "a",
        "Secrets detection",
        None,
        [Match("apikey", "apikey", 0, 0, 0, 0)],
    )
    cache = Cache()

    cache.add_found_policy_break(
        policy_break.break_type, get_ignore_sha(policy_break), "a"
    )
    cache.add_found_policy_break(
        policy_break.break_type, get_ignore_sha(policy_break), "b"
    )

    assert len(cache.last_found_secrets) == 1


def test_ignore_last_found_preserve_previous_config(client, isolated_fs):
    """
    GIVEN a cache containing new secrets AND a config not empty
    WHEN I run ignore command
    THEN existing config option are not wiped out
    """
    config = Config()
    previous_secrets = [
        IgnoredMatch(name="", match="previous_secret"),
        IgnoredMatch(name="", match="other_previous_secret"),
    ]

    previous_paths = {"some_path", "some_other_path"}
    config.user_config.secret.ignored_matches = previous_secrets.copy()
    config.user_config.secret.ignored_paths = previous_paths
    config.user_config.exit_zero = True

    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS
    ignore_last_found(config, cache)
    matches_ignore = sorted(
        config.user_config.secret.ignored_matches, key=compare_matches_ignore
    )

    found_secrets = sorted(FOUND_SECRETS + previous_secrets, key=compare_matches_ignore)

    assert matches_ignore == found_secrets
    assert config.user_config.secret.ignored_paths == previous_paths
    assert config.user_config.exit_zero is True
