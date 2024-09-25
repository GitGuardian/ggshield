import logging
from pathlib import Path
from subprocess import CalledProcessError

import pytest

from tests.conftest import GG_VALID_TOKEN
from tests.functional.utils import recreate_censored_content
from tests.repository import Repository


HOOK_CONTENT = """#!/bin/sh
set -e
ggshield secret scan pre-receive
"""


def test_scan_prereceive(tmp_path: Path) -> None:
    # GIVEN a remote repository
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    # AND a local clone
    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")

    # AND ggshield installed as a pre-receive hook
    hook_path = remote_repo.path / "hooks" / "pre-receive"
    hook_path.write_text(HOOK_CONTENT)
    hook_path.chmod(0o755)

    # AND a secret committed
    secret_file = local_repo.path / "secret.conf"
    secret_content = f"password = {GG_VALID_TOKEN}"
    secret_file.write_text(secret_content)
    local_repo.add("secret.conf")
    local_repo.create_commit()

    # WHEN I try to push
    # THEN the hook prevents the push
    with pytest.raises(CalledProcessError) as exc:
        local_repo.push()

    # AND the error message contains the leaked secret
    stderr = exc.value.stderr.decode()
    assert recreate_censored_content(secret_content, GG_VALID_TOKEN) in stderr


def test_scan_prereceive_branch_without_new_commits(tmp_path: Path) -> None:
    # GIVEN a remote repository
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    # AND a local clone
    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")

    # Add a commit to the remote repository, otherwise git complains the branch does not
    # contain anything
    local_repo.create_commit()
    local_repo.push()

    # AND ggshield installed as a pre-receive hook
    hook_path = remote_repo.path / "hooks" / "pre-receive"
    hook_path.write_text(HOOK_CONTENT)
    hook_path.chmod(0o755)

    # AND a branch without new commits
    branch_name = "topic"
    local_repo.create_branch(branch_name)

    # WHEN I try to push the branch
    # THEN the hook does not crash
    local_repo.push("-u", "origin", branch_name)


def test_scan_prereceive_push_force(tmp_path: Path) -> None:
    # GIVEN a remote repository
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    # AND a local clone
    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")
    initial_sha = local_repo.create_commit("Initial commit")

    # AND a secret committed and pushed
    secret_file = local_repo.path / "secret.conf"
    secret_content = f"password = {GG_VALID_TOKEN}"
    secret_file.write_text(secret_content)
    local_repo.add("secret.conf")
    local_repo.create_commit()
    local_repo.push()

    # AND ggshield installed as a pre-receive hook
    hook_path = remote_repo.path / "hooks" / "pre-receive"
    hook_path.write_text(HOOK_CONTENT)
    hook_path.chmod(0o755)

    # AND a commit overwriting the leak commit
    local_repo.git("reset", "--hard", initial_sha)
    secret_file.write_text("password = $FROM_ENV")
    local_repo.add("secret.conf")
    local_repo.create_commit()

    # WHEN I push force to overwrite the commit with the secret
    # THEN the push is accepted because the commit containing the secret has not been
    # scanned
    local_repo.push("--force")


def test_scan_prereceive_timeout(
    tmp_path: Path, monkeypatch, slow_gitguardian_api: str, caplog
) -> None:
    # GIVEN a remote repository
    remote_repo = Repository.create(tmp_path / "remote", bare=True)

    # AND a local clone
    local_repo = Repository.clone(remote_repo.path, tmp_path / "local")

    # AND ggshield installed as a pre-receive hook
    hook_path = remote_repo.path / "hooks" / "pre-receive"
    hook_path.write_text(HOOK_CONTENT)
    hook_path.chmod(0o755)

    # AND a secret committed
    secret_file = local_repo.path / "secret.conf"
    secret_content = f"password = {GG_VALID_TOKEN}"
    secret_file.write_text(secret_content)
    local_repo.add("secret.conf")
    local_repo.create_commit()

    # WHEN I try to push
    # THEN the hook timeouts and allows the push
    with caplog.at_level(logging.WARNING):
        monkeypatch.setenv("GITGUARDIAN_API_URL", slow_gitguardian_api)
        monkeypatch.delenv("GITGUARDIAN_INSTANCE", raising=False)
        local_repo.push()

    # AND the error message contains timeout message
    assert any(
        "Pre-receive hook took too long" in record.message
        for record in caplog.records
        if record.levelname == "WARNING"
    )
