from mock import patch
from pygitguardian.models import Match, PolicyBreak

from ggshield.config import Cache, Config
from ggshield.ignore import ignore_last_found
from ggshield.scan import Commit
from tests.conftest import _MULTIPLE_SECRETS, my_vcr


FOUND_SECRETS = [
    {
        "name": "port",
        "match": "41b8889e5e794b21cb1349d8eef1815960bf5257330fd40243a4895f26c2b5c8",
    },
]


def compare_matches_ignore(match):
    return (match["name"], match["match"]) if isinstance(match, dict) else (match,)


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])  # nosec
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")  # nosec
def test_cache_catches_last_found_secrets(client):
    """
    GIVEN an empty cache and an empty config matches-ignore section
    WHEN I run a scan with multiple secrets
    THEN cache last_found_secrets is updated with these secrets and saved
    """
    c = Commit()
    c._patch = _MULTIPLE_SECRETS
    config = Config()
    setattr(config, "matches_ignore", [])
    cache = Cache()
    cache.purge()
    assert cache.last_found_secrets == list()

    with my_vcr.use_cassette("multiple_secrets"):
        c.scan(
            client=client,
            cache=cache,
            matches_ignore=config.matches_ignore,
            all_policies=True,
            verbose=False,
            mode_header="test",
        )
    assert config.matches_ignore == list()

    cache_found_secrets = sorted(cache.last_found_secrets, key=compare_matches_ignore)
    found_secrets = sorted(FOUND_SECRETS, key=compare_matches_ignore)

    assert [found_secret["match"] for found_secret in cache_found_secrets] == [
        found_secret["match"] for found_secret in found_secrets
    ]
    ignore_last_found(config, cache)
    for ignore in config.matches_ignore:
        assert "test.txt" in ignore["name"]
    cache.load_cache()


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])  # nosec
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")  # nosec
def test_cache_catches_nothing(client):
    """
    GIVEN a cache of last found secrets same as config ignored-matches
    WHEN I run a scan (therefore finding no secret)
    THEN config matches is unchanged and cache is empty
    """
    c = Commit()
    c._patch = _MULTIPLE_SECRETS
    config = Config()
    config.matches_ignore = FOUND_SECRETS
    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS

    with my_vcr.use_cassette("multiple_secrets"):
        results = c.scan(
            client=client,
            cache=cache,
            matches_ignore=config.matches_ignore,
            all_policies=True,
            verbose=False,
            mode_header="test",
        )

        assert results == []
        assert config.matches_ignore == FOUND_SECRETS
        assert cache.last_found_secrets == []


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])  # nosec
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")  # nosec
def test_cache_old_config_no_new_secret(client):
    """
    GIVEN a cache of last found secrets same as config ignored-matches
          and config ignored-matches is a list of strings
    WHEN I run a scan (therefore finding no secret)
    THEN config matches is unchanged and cache is empty
    """
    c = Commit()
    c._patch = _MULTIPLE_SECRETS
    config = Config()
    config.matches_ignore = [d["match"] for d in FOUND_SECRETS]
    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS

    with my_vcr.use_cassette("multiple_secrets"):
        results = c.scan(
            client=client,
            cache=cache,
            matches_ignore=config.matches_ignore,
            all_policies=True,
            verbose=False,
            mode_header="test",
        )

        assert results == []
        assert config.matches_ignore == [d["match"] for d in FOUND_SECRETS]
        assert cache.last_found_secrets == []


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])  # nosec
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")  # nosec
def test_ignore_last_found(client):
    """
    GIVEN a cache of last found secrets not empty
    WHEN I run a ignore last found command
    THEN config ignored-matches is updated accordingly
    """
    config = Config()
    setattr(config, "matches_ignore", list())

    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS
    ignore_last_found(config, cache)

    matches_ignore = sorted(config.matches_ignore, key=compare_matches_ignore)

    found_secrets = sorted(FOUND_SECRETS, key=compare_matches_ignore)

    assert matches_ignore == found_secrets
    assert cache.last_found_secrets == FOUND_SECRETS


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])  # nosec
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")  # nosec
def test_ignore_last_found_with_manually_added_secrets(client):
    """
    GIVEN a cache containing part of config ignored-matches secrets
    WHEN I run ignore command
    THEN only new discovered secrets are added to the config
    """
    manually_added_secret = (
        "41b8889e5e794b21cb1349d8eef1815960bf5257330fd40243a4895f26c2b5c8"
    )
    config = Config()
    config.matches_ignore = [{"name": "", "match": manually_added_secret}]
    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS

    ignore_last_found(config, cache)

    matches_ignore = sorted(config.matches_ignore, key=compare_matches_ignore)

    found_secrets = sorted(FOUND_SECRETS, key=compare_matches_ignore)
    assert matches_ignore == found_secrets


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])  # nosec
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")  # nosec
def test_do_not_duplicate_last_found_secrets(client):
    """
    GIVEN 2 policy breaks on different files with the same ignore sha
    WHEN add_found_policy_break is called
    THEN only one element should be added
    """
    policy_break = PolicyBreak(
        "a", "Secrets detection", [Match("apikey", "apikey", 0, 0, 0, 0)]
    )
    cache = Cache()

    cache.add_found_policy_break(policy_break, "a")
    cache.add_found_policy_break(policy_break, "b")

    assert len(cache.last_found_secrets) == 1


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])  # nosec
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")  # nosec
def test_do_not_add_policy_breaks_to_last_found(client):
    """
    GIVEN 2 policy breaks on different files with the same ignore sha
    WHEN add_found_policy_break is called
    THEN only one element should be added
    """
    policy_break = PolicyBreak(
        "a", "gitignore", [Match("apikey", "apikey", 0, 0, 0, 0)]
    )
    cache = Cache()

    cache.add_found_policy_break(policy_break, "a")

    assert len(cache.last_found_secrets) == 0


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])  # nosec
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")  # nosec
def test_ignore_last_found_preserve_previous_config(client):
    """
    GIVEN a cache containing new secrets AND a config not empty
    WHEN I run ignore command
    THEN existing config option are not wiped out
    """
    config = Config()
    previous_secrets = [
        {"name": "", "match": "previous_secret"},
        {"name": "", "match": "other_previous_secret"},
    ]

    previous_paths = {"some_path", "some_other_path"}
    config.matches_ignore = previous_secrets.copy()
    config.paths_ignore = previous_paths
    config.exit_zero = True

    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS
    ignore_last_found(config, cache)
    matches_ignore = sorted(config.matches_ignore, key=compare_matches_ignore)

    found_secrets = sorted(FOUND_SECRETS + previous_secrets, key=compare_matches_ignore)

    assert matches_ignore == found_secrets
    assert config.paths_ignore == previous_paths
    assert config.exit_zero is True


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])  # nosec
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")  # nosec
def test_ignore_last_found_compatible_with_previous_matches_ignore_format(client):
    """
    GIVEN a cache containing new secrets
        AND a config's matches_ignore not empty as a list of strings
    WHEN I run ignore command
    THEN config's matches_ignore is updated AND strings hashes are unchanged
    """
    config = Config()
    old_format_matches_ignore = [
        "some_secret_hash",
        "another_secret_hash",
    ]
    config.matches_ignore = old_format_matches_ignore.copy()

    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS
    ignore_last_found(config, cache)

    assert sorted(config.matches_ignore, key=compare_matches_ignore) == sorted(
        FOUND_SECRETS + old_format_matches_ignore, key=compare_matches_ignore
    )
