from pathlib import Path

from utils import run_ggshield_scan

from tests.repository import Repository


def test_scan_repo(tmp_path: Path) -> None:
    repo = Repository.create(tmp_path)
    test_file = repo.path / "test"
    for n in range(10):
        test_file.write_text(f"Hello {n}")
        repo.git("add", test_file)
        repo.create_commit(message=f"Hello {n}")

    run_ggshield_scan("repo", str(repo.path), expected_code=0)
