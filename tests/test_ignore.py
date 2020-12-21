from mock import patch

from ggshield.config import Cache, Config
from ggshield.ignore import ignore_last_found
from ggshield.scan import Commit
from tests.conftest import _MULTIPLE_SECRETS, my_vcr


FOUND_SECRETS = {
    "5434",
    "google.com",
    "m42ploz2wd",
    "root",
}


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
    setattr(config, "matches_ignore", set())
    cache = Cache()
    cache.purge()
    assert cache.last_found_secrets == set()

    with my_vcr.use_cassette("multiple_secrets"):
        c.scan(
            client=client,
            cache=cache,
            matches_ignore=config.matches_ignore,
            all_policies=True,
            verbose=False,
        )
    assert config.matches_ignore == set()
    assert cache.last_found_secrets == FOUND_SECRETS
    cache.load_cache()
    assert cache.last_found_secrets == FOUND_SECRETS


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
        assert cache.last_found_secrets == set()


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")
def test_ignore_last_found(client):
    """
    GIVEN a cache of last found secrets not empty
    WHEN I run a ignore last found command
    THEN config ignored-matches is updated accordingly
    """
    config = Config()
    setattr(config, "matches_ignore", set())

    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS
    ignore_last_found(config, cache)
    assert config.matches_ignore == FOUND_SECRETS
    assert cache.last_found_secrets == FOUND_SECRETS


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")
def test_ignore_last_found_with_manually_added_secrets(client):
    """
    GIVEN a cache containing part of config ignored-matches secrets
    WHEN I run ignore command
    THEN only new discovered secrets are added to the config
    """
    manually_added_secret = "m42ploz2wd"
    config = Config()
    config.matches_ignore = {manually_added_secret}
    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS

    ignore_last_found(config, cache)

    assert config.matches_ignore == FOUND_SECRETS


@patch("ggshield.config.Config.CONFIG_LOCAL", ["/tmp/.gitguardian.yml"])
@patch("ggshield.config.Config.DEFAULT_CONFIG_LOCAL", "/tmp/.gitguardian.yml")
def test_ignore_last_found_preserve_previous_config(client):
    """
    GIVEN a cache containing new secrets AND a config not empty
    WHEN I run ignore command
    THEN existing config option are not wiped out
    """
    config = Config()
    previous_secrets = {"previous_secret", "other_previous_secret"}
    previous_paths = {"some_path", "some_other_path"}
    config.matches_ignore = previous_secrets
    config.paths_ignore = previous_paths
    config.exit_zero = True

    cache = Cache()
    cache.last_found_secrets = FOUND_SECRETS

    ignore_last_found(config, cache)

    assert config.matches_ignore == FOUND_SECRETS.union(previous_secrets)
    assert config.paths_ignore == previous_paths
    assert config.exit_zero is True
