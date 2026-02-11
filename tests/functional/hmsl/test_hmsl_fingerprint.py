"""
Functional tests for the HMSL fingerprint command, focusing on secret filtering.
"""

from pathlib import Path

from tests.functional.utils import run_ggshield


def test_fingerprint_filters_short_secrets(tmp_path: Path) -> None:
    """
    GIVEN a file with secrets of various lengths
    WHEN running the fingerprint command
    THEN only secrets >= 6 characters are processed
    """
    secrets_file = tmp_path / "secrets.txt"
    secrets_file.write_text(
        "abc\n"  # 3 chars - filtered
        "12345\n"  # 5 chars - filtered
        "123456\n"  # 6 chars - kept
        "validSecretHere\n"  # 15 chars - kept
    )

    result = run_ggshield(
        "hmsl", "fingerprint", str(secrets_file), cwd=tmp_path, expected_code=0
    )

    # Should report 2 secrets prepared (the two >= 6 chars)
    assert "Prepared 2 secrets" in result.stderr


def test_fingerprint_filters_excluded_values(tmp_path: Path) -> None:
    """
    GIVEN a file with excluded placeholder values
    WHEN running the fingerprint command
    THEN excluded values are filtered out
    """
    secrets_file = tmp_path / "secrets.txt"
    secrets_file.write_text(
        "changeme\n"  # excluded value
        "placeholder\n"  # excluded value
        "validSecretHere\n"  # valid secret
    )

    result = run_ggshield(
        "hmsl", "fingerprint", str(secrets_file), cwd=tmp_path, expected_code=0
    )

    # Should report 1 secret prepared (only the valid one)
    assert "Prepared 1 secrets" in result.stderr


def test_fingerprint_short_circuits_when_all_filtered(tmp_path: Path) -> None:
    """
    GIVEN a file where all secrets are too short
    WHEN running the fingerprint command
    THEN the command short-circuits with appropriate message
    """
    secrets_file = tmp_path / "secrets.txt"
    secrets_file.write_text(
        "abc\n"  # 3 chars - filtered
        "12345\n"  # 5 chars - filtered
        "short\n"  # 5 chars - filtered
    )

    result = run_ggshield(
        "hmsl", "fingerprint", str(secrets_file), cwd=tmp_path, expected_code=0
    )

    # Should indicate no secrets to prepare
    assert "No secrets to prepare" in result.stderr

    # No output files should be created
    assert not (tmp_path / "payload.txt").exists()
    assert not (tmp_path / "mapping.txt").exists()


def test_fingerprint_env_filters_excluded_keys(tmp_path: Path) -> None:
    """
    GIVEN an env file with excluded keys (HOST, PORT)
    WHEN running the fingerprint command with --type env
    THEN excluded keys are filtered out
    """
    env_file = tmp_path / ".env"
    env_file.write_text(
        "API_KEY=mysupersecretkey123\n"  # valid
        "HOST=192.168.1.1\n"  # excluded key
        "PORT=8080\n"  # excluded key (also short value)
        "DB_PASSWORD=anothersecretvalue\n"  # valid
    )

    result = run_ggshield(
        "hmsl",
        "fingerprint",
        "--type",
        "env",
        str(env_file),
        cwd=tmp_path,
        expected_code=0,
    )

    # Should report 2 secrets prepared (API_KEY and DB_PASSWORD)
    assert "Prepared 2 secrets" in result.stderr
