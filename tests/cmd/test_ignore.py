import os
import tempfile

from pygitguardian.models import Match, PolicyBreak

from ggshield.cmd.secret.ignore import ignore_last_found
from ggshield.core.cache import Cache
from ggshield.core.config import Config
from ggshield.core.types import IgnoredMatch
from ggshield.core.utils import ScanContext, ScanMode
from ggshield.scan import Commit
from tests.conftest import _MULTIPLE_SECRETS_PATCH, my_vcr


DOT_GITGUARDIAN_YAML = os.path.join(tempfile.gettempdir(), ".gitguardian.yml")

FOUND_SECRETS = [
    IgnoredMatch(
        name="MySQL Assignment - test.txt",
        match="41b8889e5e794b21cb1349d8eef1815960bf5257330fd40243a4895f26c2b5c8",
    )
]


def compare_matches_ignore(match):
    return (match.name, match.match) if isinstance(match, IgnoredMatch) else (match,)


def test_cache_catches_last_found_secrets(client, isolated_fs):
    """
    GIVEN an empty cache and an empty config ignored_matches section
    WHEN I run a scan with multiple secrets
    THEN cache last_found_secrets is updated with these secrets and saved
    """
    c = Commit()
    c._patch = _MULTIPLE_SECRETS_PATCH
    config = Config()
    cache = Cache()
    cache.purge()
    assert cache.last_found_secrets == list()

    with my_vcr.use_cassette("multiple_secrets"):
        c.scan(
            client=client,
            cache=cache,
            matches_ignore=config.secret.ignored_matches,
            scan_context=ScanContext(
                scan_mode=ScanMode.COMMIT_RANGE,
                command_path="external",
            ),
        )
    assert config.secret.ignored_matches == list()

    cache_found_secrets = sorted(cache.last_found_secrets, key=compare_matches_ignore)
    found_secrets = sorted(FOUND_SECRETS, key=compare_matches_ignore)

    assert [found_secret.match for found_secret in cache_found_secrets] == [
        found_secret.match for found_secret in found_secrets
    ]
    ignore_last_found(config, cache)
    for ignore in config.secret.ignored_matches:
        assert "test.txt" in ignore.name
    cache.load_cache()


def test_cache_catches_nothing(client, isolated_fs):
    """
    GIVEN a cache of last found secrets same as config ignored-matches
    WHEN I run a scan (therefore finding no secret)
    THEN config matches is unchanged and cache is empty
    """
    c = Commit()
    c._patch = _MULTIPLE_SECRETS_PATCH
    config = Config()
    config.secret.ignored_matches = FOUND_SECRETS
    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS

    with my_vcr.use_cassette("multiple_secrets"):
        results = c.scan(
            client=client,
            cache=cache,
            matches_ignore=config.secret.ignored_matches,
            scan_context=ScanContext(
                scan_mode=ScanMode.COMMIT_RANGE,
                command_path="external",
            ),
        )

        assert results.results == []
        assert config.secret.ignored_matches == FOUND_SECRETS
        assert cache.last_found_secrets == []


def test_ignore_last_found(client, isolated_fs):
    """
    GIVEN a cache of last found secrets not empty
    WHEN I run a ignore last found command
    THEN config ignored-matches is updated accordingly
    """
    config = Config()

    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS
    ignore_last_found(config, cache)

    matches_ignore = sorted(config.secret.ignored_matches, key=compare_matches_ignore)

    found_secrets = sorted(FOUND_SECRETS, key=compare_matches_ignore)

    assert matches_ignore == found_secrets
    assert cache.last_found_secrets == FOUND_SECRETS


def test_ignore_last_found_with_manually_added_secrets(client, isolated_fs):
    """
    GIVEN a cache containing part of config ignored-matches secrets
    WHEN I run ignore command
    THEN only new discovered secrets are added to the config
    """
    manually_added_secret = (
        "41b8889e5e794b21cb1349d8eef1815960bf5257330fd40243a4895f26c2b5c8"
    )
    config = Config()
    config.secret.ignored_matches = [IgnoredMatch(name="", match=manually_added_secret)]
    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS

    ignore_last_found(config, cache)

    matches_ignore = sorted(config.secret.ignored_matches, key=compare_matches_ignore)

    found_secrets = sorted(FOUND_SECRETS, key=compare_matches_ignore)
    assert matches_ignore == found_secrets


def test_do_not_duplicate_last_found_secrets(client, isolated_fs):
    """
    GIVEN 2 policy breaks on different files with the same ignore sha
    WHEN add_found_policy_break is called
    THEN only one element should be added
    """
    policy_break = PolicyBreak(
        "a", "Secrets detection", None, [Match("apikey", "apikey", 0, 0, 0, 0)]
    )
    cache = Cache()

    cache.add_found_policy_break(policy_break, "a")
    cache.add_found_policy_break(policy_break, "b")

    assert len(cache.last_found_secrets) == 1


def test_do_not_add_policy_breaks_to_last_found(client, isolated_fs):
    """
    GIVEN 1 policy breaks on different files with the same ignore sha
    WHEN add_found_policy_break is called
    THEN only one element should be added
    """
    policy_break = PolicyBreak(
        "a", "gitignore", None, [Match("apikey", "apikey", 0, 0, 0, 0)]
    )
    cache = Cache()

    cache.add_found_policy_break(policy_break, "a")

    assert len(cache.last_found_secrets) == 0


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
    config.secret.ignored_matches = previous_secrets.copy()
    config.secret.ignored_paths = previous_paths
    config.exit_zero = True

    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS
    ignore_last_found(config, cache)
    matches_ignore = sorted(config.secret.ignored_matches, key=compare_matches_ignore)

    found_secrets = sorted(FOUND_SECRETS + previous_secrets, key=compare_matches_ignore)

    assert matches_ignore == found_secrets
    assert config.secret.ignored_paths == previous_paths
    assert config.exit_zero is True
