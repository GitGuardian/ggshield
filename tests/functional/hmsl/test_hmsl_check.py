"""
Functional tests for the HMSL check command, focusing on secret filtering.
"""

from pathlib import Path

from tests.functional.utils import run_ggshield


def test_check_short_circuits_when_all_filtered(tmp_path: Path) -> None:
    """
    GIVEN a file where all secrets are too short or excluded
    WHEN running the check command
    THEN the command short-circuits without calling the API
    """
    secrets_file = tmp_path / "secrets.txt"
    secrets_file.write_text(
        "abc\n"  # 3 chars - filtered
        "12345\n"  # 5 chars - filtered
        "changeme\n"  # excluded value
    )

    result = run_ggshield(
        "hmsl", "check", str(secrets_file), cwd=tmp_path, expected_code=0
    )

    # Should indicate no secrets found (short-circuit, no API call)
    assert "Collected 0 secrets" in result.stderr
    assert "No leaked secret has been found" in result.stderr


def test_check_env_filters_excluded_keys_and_values(tmp_path: Path) -> None:
    """
    GIVEN an env file with only excluded keys and values
    WHEN running the check command with --type env
    THEN the command short-circuits without calling the API
    """
    env_file = tmp_path / ".env"
    env_file.write_text(
        "HOST=192.168.1.1\n"  # excluded key
        "PORT=8080\n"  # excluded key
        "DEBUG=placeholder\n"  # excluded value
        "MODE=changeme\n"  # excluded value
    )

    result = run_ggshield(
        "hmsl", "check", "--type", "env", str(env_file), cwd=tmp_path, expected_code=0
    )

    # Should indicate no secrets found (short-circuit, no API call)
    assert "Collected 0 secrets" in result.stderr
    assert "No leaked secret has been found" in result.stderr
