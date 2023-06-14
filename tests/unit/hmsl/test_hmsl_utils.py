from unittest.mock import MagicMock

import pytest
from pygitguardian.client import GGClient
from pygitguardian.models import JWTResponse

from ggshield.core.config.config import Config
from ggshield.hmsl.utils import get_token, load_token_from_disk


@pytest.fixture
def hmsl_no_env_vars(monkeypatch):
    monkeypatch.delenv("GITGUARDIAN_SAAS_URL", raising=False)
    monkeypatch.delenv("GITGUARDIAN_SAAS_API_KEY", raising=False)
    monkeypatch.delenv("GITGUARDIAN_HMSL_URL", raising=False)
    monkeypatch.delenv("GITGUARDIAN_HMSL_AUDIENCE", raising=False)


@pytest.fixture
def create_jwt_mock(monkeypatch):
    mock = MagicMock(return_value=JWTResponse(token="dummy_token"))
    monkeypatch.setenv("GITGUARDIAN_SAAS_API_KEY", "dummy_api_key")
    monkeypatch.setattr(GGClient, "create_jwt", mock)
    return mock


def test_hmsl_config_values(isolated_fs, hmsl_no_env_vars):
    """
    GIVEN the default config
    WHEN getting HasMySecretLeaked config values
    THEN the values are correctly set
    """
    config = Config()
    assert config.hmsl_url == "https://hasmysecretleaked.gitguardian.com"
    assert config.hmsl_audience == "https://hasmysecretleaked.gitguardian.com"
    assert config.saas_api_url == "https://api.gitguardian.com"


def test_no_token(isolated_fs, hmsl_no_env_vars):
    """
    GIVEN the default config (not authenticated)
    WHEN getting a token
    THEN we receive nothing
    """
    config = Config()
    token = get_token(config)
    assert token is None


def test_get_token(isolated_fs, create_jwt_mock: MagicMock):
    """
    GIVEN a logged in session to GIM
    WHEN requesting a token
    THEN we receive it
    """
    config = Config()
    assert load_token_from_disk() is None
    token = get_token(config)
    create_jwt_mock.assert_called_once()
    assert token == "dummy_token"
