from pathlib import Path

from tests.functional.utils import run_ggshield
from tests.repository import Repository


def test_install_local_detects_husky(tmp_path: Path) -> None:
    repo = Repository.create(tmp_path)

    husky_dir = repo.path / ".husky"
    (husky_dir / "_").mkdir(parents=True)
    repo.git("config", "core.hooksPath", ".husky/_")

    run_ggshield("install", "-m", "local", "-t", "pre-commit", cwd=repo.path)

    husky_hook = husky_dir / "pre-commit"
    assert husky_hook.is_file()
    assert 'ggshield secret scan pre-commit "$@"' in husky_hook.read_text()

    default_hook = repo.path / ".git/hooks/pre-commit"
    assert not default_hook.exists()
