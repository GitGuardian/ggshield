import stat
import sys
from unittest.mock import patch

import pytest

from ggshield.core.config.config import Config, ConfigSource
from ggshield.core.config.system_auth import (
    SystemAuth,
    get_system_auth_path,
    read_system_auth,
    write_system_auth,
)
from ggshield.core.errors import UnknownInstanceError


CFG = "ggshield.core.config.config.read_system_auth"


@pytest.fixture()
def system_config_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("GG_SYSTEM_CONFIG_DIR", str(tmp_path))
    yield tmp_path


class TestSystemAuthFile:
    def test_read_absent_returns_none(self, system_config_dir):
        assert read_system_auth() is None

    def test_write_then_read_roundtrip(self, system_config_dir):
        write_system_auth("https://fleet.example.com", "sa-token")
        result = read_system_auth()
        assert result == SystemAuth(instance="https://fleet.example.com", token="sa-token")

    def test_read_malformed_returns_none(self, system_config_dir):
        get_system_auth_path().write_text("this: is: not: valid: yaml: [", encoding="utf-8")
        assert read_system_auth() is None

    def test_read_missing_keys_returns_none(self, system_config_dir):
        get_system_auth_path().write_text("instance: https://x\n", encoding="utf-8")
        assert read_system_auth() is None  # token missing

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX file mode bits")
    def test_write_is_world_readable(self, system_config_dir):
        path = write_system_auth("https://x", "sa-token")
        assert stat.S_IMODE(path.stat().st_mode) == 0o644


class TestSystemConfigFallback:
    """Config resolution falls back to the machine-wide service-account token."""

    def test_api_key_falls_back_to_system_token(self, monkeypatch):
        monkeypatch.delenv("GITGUARDIAN_API_KEY", raising=False)
        config = Config()
        config.user_config.instance = "https://fleet.example.com"
        sa = SystemAuth(instance="https://fleet.example.com", token="sa-token")
        with patch(CFG, return_value=sa):
            key, source = config.get_api_key_and_source()
        assert key == "sa-token"
        assert source == ConfigSource.SYSTEM_CONFIG

    def test_system_token_ignored_on_instance_mismatch(self, monkeypatch):
        monkeypatch.delenv("GITGUARDIAN_API_KEY", raising=False)
        config = Config()
        config.user_config.instance = "https://fleet.example.com"
        sa = SystemAuth(instance="https://other.example.com", token="sa-token")
        with patch(CFG, return_value=sa):
            with pytest.raises(UnknownInstanceError):
                config.api_key

    def test_env_var_wins_over_system_token(self, monkeypatch):
        monkeypatch.setenv("GITGUARDIAN_API_KEY", "env-key")
        config = Config()
        sa = SystemAuth(instance="https://fleet.example.com", token="sa-token")
        with patch(CFG, return_value=sa):
            key, source = config.get_api_key_and_source()
        assert key == "env-key"
        assert source in (ConfigSource.ENV_VAR, ConfigSource.DOTENV)

    def test_instance_falls_back_to_system(self, monkeypatch):
        monkeypatch.delenv("GITGUARDIAN_INSTANCE", raising=False)
        monkeypatch.delenv("GITGUARDIAN_API_URL", raising=False)
        config = Config()
        config.user_config.instance = None
        sa = SystemAuth(instance="https://fleet.example.com", token="sa-token")
        with patch(CFG, return_value=sa):
            name, source = config.get_instance_name_and_source()
        assert name == "https://fleet.example.com"
        assert source == ConfigSource.SYSTEM_CONFIG
