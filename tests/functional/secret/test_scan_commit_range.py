from pathlib import Path

from tests.conftest import GG_VALID_TOKEN
from tests.functional.utils import recreate_censored_content, run_ggshield_scan
from tests.repository import Repository


def test_scan_commit_range(tmp_path: Path) -> None:
    repo = Repository.create(tmp_path)
    test_file = repo.path / "test"
    for n in range(10):
        test_file.write_text(f"Hello {n}")
        repo.add(test_file)
        repo.create_commit(message=f"Hello {n}")

    run_ggshield_scan("commit-range", "HEAD~4...", expected_code=0, cwd=repo.path)


def test_scan_commit_range_finds_old_leak(tmp_path: Path) -> None:
    # GIVEN a repository
    repo = Repository.create(tmp_path)
    initial_sha = repo.create_commit()

    # AND a commit containing a leak
    secret_file = repo.path / "secret.conf"
    secret_content = f"password = {GG_VALID_TOKEN}"
    secret_file.write_text(secret_content)
    repo.add("secret.conf")

    # AND some clean commits on top of it
    for _ in range(3):
        repo.create_commit()

    # WHEN scanning the last two commits, it's OK
    run_ggshield_scan("commit-range", "HEAD~2...", expected_code=0, cwd=repo.path)

    # WHEN scanning from before the leak commit
    # THEN the leak is found
    proc = run_ggshield_scan(
        "commit-range", f"{initial_sha}...", expected_code=1, cwd=repo.path
    )
    assert recreate_censored_content(secret_content, GG_VALID_TOKEN) in proc.stdout
