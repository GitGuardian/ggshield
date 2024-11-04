from typing import Dict, Optional
from unittest.mock import Mock, patch

import pytest

from ggshield.core.env_utils import TRACKED_ENV_VARS, load_dot_env
from ggshield.utils.os import cd


@patch("ggshield.core.env_utils.load_dotenv")
@pytest.mark.parametrize(
    ["cwd", "env", "expected_dotenv_path"],
    [
        ("sub", {}, None),
        (".", {}, ".env"),
        (".", {"GITGUARDIAN_DONT_LOAD_ENV": "1"}, None),
        (".", {"GITGUARDIAN_DOTENV_PATH": ".custom-env"}, ".custom-env"),
        (".", {"GITGUARDIAN_DOTENV_PATH": ".does-not-exist"}, None),
    ],
)
def test_load_dot_env(
    load_dotenv_mock: Mock,
    monkeypatch,
    tmp_path,
    cwd: str,
    env: Dict[str, str],
    expected_dotenv_path: Optional[str],
):
    """
    GIVEN a file hierarchy like this:
    /sub/
    /.env
    /.custom-env
    AND environment variables set according to `env`
    AND the current working directory being `/sub/`
    WHEN load_dot_env() is called
    THEN the appropriate environment file is loaded
    """
    (tmp_path / "sub").mkdir()
    (tmp_path / ".env").touch()
    (tmp_path / ".custom-env").touch()

    if env:
        for key, value in env.items():
            monkeypatch.setenv(key, value)

    with cd(tmp_path / cwd):
        load_dot_env()

        if expected_dotenv_path:
            expected_dotenv_path = tmp_path / expected_dotenv_path
            load_dotenv_mock.assert_called_once_with(
                expected_dotenv_path, override=True
            )
        else:
            load_dotenv_mock.assert_not_called()


@patch("ggshield.core.env_utils.get_git_root")
@patch("ggshield.core.env_utils.is_git_dir")
@patch("ggshield.core.env_utils.load_dotenv")
def test_load_dot_env_loads_git_root_env(
    load_dotenv_mock: Mock, is_git_dir_mock, get_git_root_mock, tmp_path
):
    """
    GIVEN a git repository checkout with this file hierarchy:
    /sub1/sub2
    /sub1/.env
    /.env
    AND the current working directory being `/sub1/sub2`
    WHEN load_dot_env() is called
    THEN the .env file at the root of the git repository is loaded
    """
    is_git_dir_mock.return_value = True
    get_git_root_mock.return_value = tmp_path

    sub1_sub2_dir = tmp_path / "sub1" / "sub2"
    git_root_dotenv = tmp_path / ".env"

    sub1_sub2_dir.mkdir(parents=True)
    (tmp_path / "sub1" / ".env").touch()
    git_root_dotenv.touch()

    with cd(sub1_sub2_dir):
        load_dot_env()
        load_dotenv_mock.assert_called_once_with(git_root_dotenv, override=True)


@pytest.mark.parametrize("env_var", sorted(TRACKED_ENV_VARS))
def test_load_dot_env_returns_set_vars(env_var, tmp_path, monkeypatch):
    """
    GIVEN an env var that is set, and also set with the same value in the .env
    WHEN load_dot_env() is called
    THEN it returns the env var
    """
    monkeypatch.setenv(env_var, "value")
    (tmp_path / ".env").write_text(f"{env_var}=value")
    with cd(tmp_path):
        set_variables = load_dot_env()

    assert set_variables == {env_var}
