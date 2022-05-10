from pathlib import Path
from subprocess import CalledProcessError

import pytest
from utils import run_ggshield

from tests.conftest import GG_VALID_TOKEN
from tests.repository import Repository


def test_scan_prepush(tmp_path: Path) -> None:
    remote_repo = Repository.create(tmp_path / "remote")
    remote_repo.create_commit()

    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")
    run_ggshield("install", "-m", "local", "-t", "pre-push", cwd=str(local_repo.path))

    secret_file = local_repo.path / "secret.conf"
    secret_file.write_text(f"password = {GG_VALID_TOKEN}\n")
    local_repo.git("add", "secret.conf")
    local_repo.create_commit()

    with pytest.raises(CalledProcessError) as exc:
        local_repo.git("push")

    # Secret is obfuscated, so only check its first 3 chars are there
    assert f"password = {GG_VALID_TOKEN[:3]}" in exc.value.stdout.decode()
