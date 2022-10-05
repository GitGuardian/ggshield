import tarfile
from pathlib import Path

from tests.functional.utils import run_ggshield_scan


CURRENT_DIR = Path(__file__).parent


def test_scan_archive(tmp_path: Path) -> None:
    archive_path = tmp_path / "test.tar.gz"

    with tarfile.open(archive_path, "w:gz") as tar:
        for path in CURRENT_DIR.rglob("*"):
            tar.add(path)
    assert archive_path.exists()

    run_ggshield_scan("archive", str(archive_path), expected_code=0)
