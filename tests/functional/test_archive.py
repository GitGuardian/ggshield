from pathlib import Path
from subprocess import run

from utils import run_ggshield_scan


CURRENT_DIR = Path(__file__).parent


def test_scan_archive(tmp_path: Path) -> None:
    archive_path = tmp_path / "test.tar.gz"

    run(["tar", "czf", archive_path, str(CURRENT_DIR)], check=True)
    assert archive_path.exists()

    run_ggshield_scan("archive", str(archive_path), expected_code=0)
