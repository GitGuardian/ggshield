import time
from unittest.mock import MagicMock

import pytest
from pygitguardian.client import GGClient
from pygitguardian.models import JWTResponse

from ggshield.core.config.config import Config
from ggshield.verticals.hmsl.utils import (
    EXCLUDED_KEYS,
    EXCLUDED_VALUES,
    MIN_SECRET_LENGTH,
    get_token,
    is_token_valid,
    load_token_from_disk,
    remove_token_from_disk,
    should_process_secret,
)


@pytest.fixture
def hmsl_no_env_vars(monkeypatch):
    monkeypatch.delenv("GITGUARDIAN_API_KEY", raising=False)
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


def test_hmsl_default_config_values(isolated_fs, hmsl_no_env_vars):
    """
    GIVEN the default config
    WHEN getting HasMySecretLeaked config values
    THEN the values are correctly set
    """
    config = Config()
    assert config.hmsl_url == "https://api.hasmysecretleaked.com"
    assert config.hmsl_audience == "https://api.hasmysecretleaked.com"
    assert config.saas_api_url == "https://api.gitguardian.com"


def test_hmsl_other_env_config_values(isolated_fs, hmsl_no_env_vars, monkeypatch):
    """
    GIVEN a specific environment
    WHEN getting HasMySecretLeaked config values
    THEN the values are correctly set
    """
    # If the user defines a custom HMSL URL
    monkeypatch.setenv(
        "GITGUARDIAN_HMSL_URL", "https://hasmysecretleaked.env.gitguardian.com"
    )
    # They are also expected to set a corresponding GitGuardian instance
    monkeypatch.setenv("GITGUARDIAN_INSTANCE", "https://dashboard.env.gitguardian.com")
    config = Config()
    assert config.hmsl_url == "https://hasmysecretleaked.env.gitguardian.com"
    assert config.hmsl_audience == "https://hasmysecretleaked.env.gitguardian.com"
    assert config.saas_api_url == "https://api.env.gitguardian.com"


def test_hmsl_region_specific_config_values(isolated_fs, hmsl_no_env_vars, monkeypatch):
    """
    GIVEN another SaaS environment
    WHEN getting HasMySecretLeaked config values
    THEN the values are correctly set
    """
    monkeypatch.setenv(
        "GITGUARDIAN_INSTANCE", "https://dashboard.region3.gitguardian.com"
    )
    config = Config()
    assert config.hmsl_url == "https://api.hasmysecretleaked.com"
    assert config.hmsl_audience == "https://api.hasmysecretleaked.com"
    assert config.saas_api_url == "https://api.region3.gitguardian.com"


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


def test_remove_token(isolated_fs, create_jwt_mock: MagicMock):
    """
    GIVEN a logged in session to GIM
    WHEN I'm calling remove_token_from_disk
    THEN the token has been removed
    """
    config = Config()
    assert load_token_from_disk() is None
    token = get_token(config)
    create_jwt_mock.assert_called_once()
    assert token == "dummy_token"
    remove_token_from_disk()
    assert load_token_from_disk() is None


@pytest.mark.parametrize(
    "token",
    [
        "foo",
        (
            "eyJhbGciOiJSUzI1NiIsImtpZCI6Im1haW5fa2V5IiwidHlwIjoiSldUIn0.eyJzdWIiOjEsInRva2VuX2lkIjoi"
            "ZWFkNDg0MGMtN2FkNC00MTdmLWE3ZjItZGY3ZjY1YjQzMDI5IiwiYXVkIjoiaHR0cHM6Ly9oYXNteXNlY3JldGxl"
            "YWtlZDIuZ2l0Z3VhcmRpYW4uY29tIiwiaXNzIjoiaHR0cHM6Ly9kYXNoYm9hcmQuZ2l0Z3VhcmRpYW4uY29tIiwi"
            "aWF0IjoxNjgwMDAwMDAwLCJleHAiOjE2ODAwMDAxMDAsImhtc2xfcXVvdGEiOjEwMDAwMDAwLCJtZW1iZXJfaWQi"
            "OjQyfQ.BYkiuwBVUBjdma3fYfh4c6KKpbkxHc33nUbXrzT4AzETn5hyHMdns5QFyAYKUBPn0A9e4uEuPG59s0xa_"
            "TbfA_xzgCNeRtVtHR8Z464zLXlG6xtYMjsIi22P_NJSCEAzYRg3f1grWARwPUh6_DPLvNnpwL_2loFM89DdD-RQh"
            "hxAloJ5dQs9XEBH3pMku7Z81nlF45kaVOPm_vDsBAvFXETjxpgBRbNPbqoday6MmfueOE1IlGmgso61ObaNTPNt4"
            "tq_t3Wj3V1JL5hBayYQJVJRE3HzDASZ6qPpgy74vwMLBbgSVFsfuimT0ouWlhhkQXhXVaretWByNCtIyIx6vA"
        ),
        (
            "eyJhbGciOiJSUzI1NiIsImtpZCI6Im1haW5fa2V5IiwidHlwIjoiSldUIn0.eyJzdWIiOjEsInRva2VuX2lkIjoiZWF"
            "kNDg0MGMtN2FkNC00MTdmLWE3ZjItZGY3ZjY1YjQzMDI5IiwiYXVkIjoiaHR0cHM6Ly9oYXNteXNlY3JldGxlYWtlZC"
            "5naXRndWFyZGlhbi5jb20iLCJpc3MiOiJodHRwczovL2Rhc2hib2FyZC5naXRndWFyZGlhbi5jb20iLCJpYXQiOjE2N"
            "zAwMDAwMDAsImV4cCI6MTY3NTAwMDAwMCwiaG1zbF9xdW90YSI6MTAwMDAwMDAsIm1lbWJlcl9pZCI6NDJ9.imU1m_z"
            "Ddx8x50KwAKDfvyYke8avWUimairYnzMCT3CsaoYrgrBJt5vsYTkHkm7feLBwgC8rzjoHL_4j8TiqJJ1TF5x1ryxoBY"
            "wPlqnhAVYVWggvRooAmZg7eLYtnygFdrhc4M20bbJM_MB54kPbrqVRcfx3TQjga8IQX4Mb2irjafXXnga_ji5yPtRiA"
            "u7_kn5XtxypoKoUOT9o_E2sBchnmXkrYOV8zXozWfbrbiHymNzSsJM_8uuK9DHGlkUzTo7G3Ek8iRvyd7qdDU1mBEuG"
            "M9f1jAJ_j6jwiEZuT5tCWq7MtA8DZVIDB4wKn2fyZkGbuyhZLpUtg5brpPP1Vg"
        ),
    ],
)
def test_bad_token_validation(token, monkeypatch):
    """
    GIVEN an invalid token
    WHEN validating it
    THEN we receive False
    """
    monkeypatch.setattr(time, "time", lambda: 1680000001)
    assert is_token_valid(token, "https://hasmysecretleaked.gitguardian.com") is False


def test_good_token_validation(monkeypatch):
    """
    GIVEN a valid token
    WHEN validating it
    THEN we receive True
    """
    token = (
        "eyJhbGciOiJSUzI1NiIsImtpZCI6Im1haW5fa2V5IiwidHlwIjoiSldUIn0.eyJzdWIiOjEsInRva2VuX2lkIjoiZWFk"
        "NDg0MGMtN2FkNC00MTdmLWE3ZjItZGY3ZjY1YjQzMDI5IiwiYXVkIjoiaHR0cHM6Ly9oYXNteXNlY3JldGxlYWtlZC5n"
        "aXRndWFyZGlhbi5jb20iLCJpc3MiOiJodHRwczovL2Rhc2hib2FyZC5naXRndWFyZGlhbi5jb20iLCJpYXQiOjE2ODAw"
        "MDAwMDAsImV4cCI6MTY4MDAwMTAwMCwiaG1zbF9xdW90YSI6MTAwMDAwMDAsIm1lbWJlcl9pZCI6NDJ9.bJT7gxGtL2r"
        "mENKSFk7AxyFPesZpo4hIIkyTf30n88BxtPEhPPoX6xZZTBnSGAMjbye4hZ8L0_-7A7hcQAL-0qPv4F6NBB39MiaKG_l"
        "aURz15qG70hwfaeANM-IQILrkK1qr1Ir4hV8EVqXsLWFFKocWnq-fTkBqF2Qq9MkXjKxPv9Yq2nfRMCBPkVmENkP5VfJ"
        "MhiHiVIaDo3Fb9CuQ_BYkU5h5iG8QQWdI2aiM_86mTqpS3PFaJCQY6R2cxVGFEBm7TsxT3RjQ8afWteNs5zXaKz5y7U0"
        "xYC6_0VRyN66IxCL88NM6HeFO3tjHjD9roql853f8StxbcfbUSdCiXg"
    )
    monkeypatch.setattr(time, "time", lambda: 1680000001)
    assert is_token_valid(token, "https://hasmysecretleaked.gitguardian.com")


@pytest.mark.parametrize(
    "value, key, expected",
    [
        # Empty value
        pytest.param("", None, False, id="empty_value"),
        # Short values (below MIN_SECRET_LENGTH)
        pytest.param(
            "a" * (MIN_SECRET_LENGTH - 1), None, False, id="too_short_boundary"
        ),
        pytest.param("abc", None, False, id="too_short_abc"),
        pytest.param("12345", None, False, id="too_short_12345"),
        # Exact MIN_SECRET_LENGTH is accepted
        pytest.param("a" * MIN_SECRET_LENGTH, None, True, id="min_length_accepted"),
        # Excluded values (case insensitive)
        *[
            pytest.param(variant, None, False, id=f"excluded_value_{value}_{form}")
            for value in sorted(EXCLUDED_VALUES)
            for form, variant in [
                ("lower", value),
                ("upper", value.upper()),
                ("capitalized", value.capitalize()),
            ]
        ],
        # Excluded keys (case insensitive)
        *[
            pytest.param(
                "some-secret-value", variant, False, id=f"excluded_key_{key}_{form}"
            )
            for key in sorted(EXCLUDED_KEYS)
            for form, variant in [("original", key), ("lower", key.lower())]
        ],
        # Vault-style path keys
        pytest.param("secret-value", "secret/app/HOST", False, id="vault_path_host"),
        pytest.param(
            "secret-value", "secret/app/prod/PORT", False, id="vault_path_port"
        ),
        # Valid secrets
        pytest.param("my-secret-api-key", None, True, id="valid_api_key"),
        pytest.param("password123456", None, True, id="valid_password"),
        pytest.param("ghp_xxxxxxxxxxxxxxxxxxxx", None, True, id="valid_ghp_token"),
        # Valid secrets with non-excluded keys
        pytest.param("my-secret-value", "API_KEY", True, id="valid_with_key"),
        pytest.param(
            "my-secret-value", "DB_PASSWORD", True, id="valid_with_db_password_key"
        ),
        pytest.param(
            "my-secret-value",
            "secret/app/API_KEY",
            True,
            id="valid_with_vault_path_key",
        ),
    ],
)
def test_should_process_secret(value, key, expected):
    """
    GIVEN a secret value and optional key
    WHEN checking if it should be processed
    THEN it returns the expected result based on validation rules
    """
    assert should_process_secret(value, key=key) is expected
