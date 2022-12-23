from pathlib import Path
from subprocess import CalledProcessError

import pytest

from tests.conftest import GG_VALID_TOKEN
from tests.functional.utils import recreate_censored_content, run_ggshield
from tests.repository import Repository


def test_scan_precommit(tmp_path: Path) -> None:
    # GIVEN a repository
    repo = Repository.create(tmp_path)

    # AND ggshield installed as a pre-commit hook
    run_ggshield("install", "-m", "local", "-t", "pre-commit", cwd=repo.path)

    # AND a secret in a file
    secret_file = repo.path / "secret.conf"
    secret_content = f"password = {GG_VALID_TOKEN}"
    secret_file.write_text(secret_content)

    # WHEN I try to commit a secret
    # THEN the hook prevents the commit
    repo.add("secret.conf")
    with pytest.raises(CalledProcessError) as exc:
        repo.create_commit()

    # AND the error message contains the leaked secret
    stderr = exc.value.stderr.decode()
    assert recreate_censored_content(secret_content, GG_VALID_TOKEN) in stderr
