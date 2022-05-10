from pathlib import Path

from tests.conftest import GG_VALID_TOKEN
from tests.functional.utils import run_ggshield_scan


def test_scan_path(tmp_path: Path) -> None:
    test_file = tmp_path / "config.py"
    test_file.write_text(f"SECRET='{GG_VALID_TOKEN}'")

    result = run_ggshield_scan("path", str(test_file), cwd=tmp_path, expected_code=1)
    assert "SECRET=" in result.stdout
