from pathlib import Path

from tests.conftest import GG_VALID_TOKEN
from tests.functional.utils import recreate_censored_content, run_ggshield_scan
from tests.repository import Repository


def test_scan_repo(tmp_path: Path) -> None:
    # GIVEN a repository
    repo = Repository.create(tmp_path)

    # AND a commit containing a leak
    secret_file = repo.path / "secret.conf"
    leak_content = f"password = {GG_VALID_TOKEN}"
    secret_file.write_text(leak_content)
    repo.git("add", "secret.conf")

    # AND some clean commits on top of it
    for _ in range(3):
        repo.create_commit()

    # WHEN scanning the repo
    # THEN the leak is found
    proc = run_ggshield_scan("repo", str(repo.path), expected_code=1, cwd=repo.path)

    assert recreate_censored_content(leak_content, GG_VALID_TOKEN) in proc.stdout
