from pathlib import Path

from utils import run_ggshield_scan


def test_scan_path(tmp_path: Path) -> None:
    test_file = tmp_path / "config.py"
    test_file.write_text("SECRET='ggtt-v-azerty1234'")  # ggignore

    result = run_ggshield_scan("path", str(test_file), expected_code=1)
    assert "SECRET=" in result.stdout
