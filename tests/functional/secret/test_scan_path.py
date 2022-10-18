from pathlib import Path

from tests.conftest import GG_VALID_TOKEN
from tests.functional.utils import recreate_censored_content, run_ggshield_scan


def test_scan_path(tmp_path: Path) -> None:
    test_file = tmp_path / "config.py"
    test_file.write_text(f"SECRET='{GG_VALID_TOKEN}'")

    result = run_ggshield_scan("path", str(test_file), cwd=tmp_path, expected_code=1)
    assert "SECRET=" in result.stdout


def test_scan_path_does_not_fail_on_long_paths(tmp_path: Path) -> None:
    # GIVEN a secret stored in a file whose path is longer than 256 characters
    secret_content = f"SECRET='{GG_VALID_TOKEN}'"

    # Create the file in a subdir because filenames cannot be longer than 255
    # characters. What we care here is the length of the path.
    test_file = tmp_path / ("d" * 255) / ("f" * 255)
    test_file.parent.mkdir()
    test_file.write_text(secret_content)

    # WHEN ggshield scans it
    result = run_ggshield_scan("path", str(test_file), cwd=tmp_path, expected_code=1)

    # THEN it finds the secret in it
    assert recreate_censored_content(secret_content, GG_VALID_TOKEN) in result.stdout
