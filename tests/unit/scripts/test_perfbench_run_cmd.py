import shutil
import subprocess
from pathlib import Path
from typing import List

import pytest
import run_cmd
from run_cmd import setup_ggshield


def make_venv(venv_dir: Path, *names: str) -> None:
    bin_dir = venv_dir / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in names:
        (bin_dir / name).touch()


@pytest.fixture
def fake_uv(monkeypatch):
    """Record `uv` calls and create the venv `uv venv` would have created"""
    calls: List[List[str]] = []

    def fake_run(args, **kwargs):
        args = [str(x) for x in args]
        calls.append(args)
        if "venv" in args:
            make_venv(Path(args[-1]), "python")
        elif "install" in args:
            python_path = Path(args[args.index("--python") + 1])
            make_venv(python_path.parent.parent, "ggshield")
        return subprocess.CompletedProcess(args, 0, stdout="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def test_current_uses_the_checkout_venv(tmp_path, monkeypatch, fake_uv):
    """
    GIVEN a checkout whose venv holds a ggshield command
    WHEN setup_ggshield() is called for "current"
    THEN it returns the checkout venv command, not whatever $PATH holds
    """
    monkeypatch.setattr(run_cmd, "REPO_DIR", tmp_path)
    make_venv(tmp_path / ".venv", "ggshield")
    monkeypatch.setattr(shutil, "which", lambda _: "/decoy/bin/ggshield")

    path = setup_ggshield(tmp_path / "work", "current")

    assert path == tmp_path / ".venv" / "bin" / "ggshield"
    assert fake_uv == []


def test_current_fails_when_the_checkout_venv_is_missing(tmp_path, monkeypatch):
    """
    GIVEN a checkout with no venv
    WHEN setup_ggshield() is called for "current"
    THEN it exits instead of falling back to another install
    """
    monkeypatch.setattr(run_cmd, "REPO_DIR", tmp_path)

    with pytest.raises(SystemExit):
        setup_ggshield(tmp_path / "work", "current")


def test_version_is_installed_in_its_own_venv(tmp_path, monkeypatch, fake_uv):
    """
    GIVEN a released version to benchmark
    WHEN setup_ggshield() is called for it
    THEN the version is installed in a dedicated venv, built from the checkout
    interpreter and targeted by an explicit interpreter, and the returned command
    belongs to that venv
    """
    monkeypatch.setattr(run_cmd, "REPO_DIR", tmp_path)
    make_venv(tmp_path / ".venv", "python")
    work_dir = tmp_path / "work"
    venv_dir = work_dir / "ggshields" / "1.40.0"

    path = setup_ggshield(work_dir, "1.40.0")

    assert path == venv_dir / "bin" / "ggshield"
    assert fake_uv == [
        [
            "uv",
            "--no-config",
            "venv",
            "--python",
            str(tmp_path / ".venv" / "bin" / "python"),
            str(venv_dir),
        ],
        [
            "uv",
            "--no-config",
            "pip",
            "install",
            "--python",
            str(venv_dir / "bin" / "python"),
            "ggshield==1.40.0",
        ],
    ]


def test_install_fails_when_the_checkout_venv_is_missing(
    tmp_path, monkeypatch, fake_uv
):
    """
    GIVEN a checkout with no venv
    WHEN setup_ggshield() is called for a released version
    THEN it exits rather than building the venv from an unrelated interpreter
    """
    monkeypatch.setattr(run_cmd, "REPO_DIR", tmp_path)

    with pytest.raises(SystemExit):
        setup_ggshield(tmp_path / "work", "1.40.0")

    assert fake_uv == []


def test_installed_version_is_reused(tmp_path, monkeypatch, fake_uv):
    """
    GIVEN a version already installed in the work dir
    WHEN setup_ggshield() is called for it
    THEN it is not installed again
    """
    monkeypatch.setattr(run_cmd, "REPO_DIR", tmp_path)
    work_dir = tmp_path / "work"
    make_venv(work_dir / "ggshields" / "1.40.0", "ggshield")

    path = setup_ggshield(work_dir, "1.40.0")

    assert path == work_dir / "ggshields" / "1.40.0" / "bin" / "ggshield"
    assert fake_uv == []


def test_explicit_path_is_used_as_is(tmp_path, monkeypatch, fake_uv):
    """
    GIVEN a path to a ggshield command
    WHEN setup_ggshield() is called with it
    THEN the path is returned untouched
    """
    monkeypatch.setattr(run_cmd, "REPO_DIR", tmp_path)
    ggshield_path = tmp_path / "somewhere" / "ggshield"
    ggshield_path.parent.mkdir()
    ggshield_path.touch()

    path = setup_ggshield(tmp_path / "work", str(ggshield_path))

    assert path == ggshield_path
    assert fake_uv == []
