from mock import patch

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


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")
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
        )
    assert config.matches_ignore == list()

    cache_found_secrets = sorted(
        cache.last_found_secrets, key=lambda match: (match["name"], match["match"])
    )
    found_secrets = sorted(
        FOUND_SECRETS, key=lambda match: (match["name"], match["match"])
    )

    assert [found_secret["match"] for found_secret in cache_found_secrets] == [
        found_secret["match"] for found_secret in found_secrets
    ]
    ignore_last_found(config, cache)
    for ignore in config.matches_ignore:
        assert "test.txt" in ignore["name"]
    cache.load_cache()


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")
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
        )

        assert results == []
        assert config.matches_ignore == FOUND_SECRETS
        assert cache.last_found_secrets == []


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")
def test_cache_old_config(client):
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
        )

        assert results == []
        assert config.matches_ignore == [d["match"] for d in FOUND_SECRETS]
        assert cache.last_found_secrets == []


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")
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

    matches_ignore = sorted(
        config.matches_ignore, key=lambda match: (match["name"], match["match"])
    )

    found_secrets = sorted(
        FOUND_SECRETS,
        key=lambda match: (match["name"], match["match"]),
    )

    assert matches_ignore == found_secrets
    assert cache.last_found_secrets == FOUND_SECRETS


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")
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

    matches_ignore = sorted(
        config.matches_ignore, key=lambda match: (match["name"], match["match"])
    )

    found_secrets = sorted(
        FOUND_SECRETS, key=lambda match: (match["name"], match["match"])
    )
    assert matches_ignore == found_secrets


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")
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
    matches_ignore = sorted(
        config.matches_ignore, key=lambda match: (match["name"], match["match"])
    )

    found_secrets = sorted(
        FOUND_SECRETS + previous_secrets,
        key=lambda match: (match["name"], match["match"]),
    )

    assert matches_ignore == found_secrets
    assert config.paths_ignore == previous_paths
    assert config.exit_zero is True
