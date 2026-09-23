import os
import stat
import sys
from pathlib import Path

import pytest

from ggshield.verticals.honeytoken import secure_file
from ggshield.verticals.honeytoken.secure_file import (
    FD_HARDENED,
    SecureFileError,
    atomic_write_path,
    atomic_write_via_fd,
    open_dir_fd,
    read_path,
    read_via_fd,
    reject_symlinked_target,
    require_safe_backend,
    unlink_via_fd,
)


posix_only = pytest.mark.skipif(not FD_HARDENED, reason="needs dir fds / O_NOFOLLOW")


# --- fd-anchored backend (POSIX) ----------------------------------------------------


@posix_only
def test_open_dir_fd_creates_a_private_dir_and_read_returns_none_when_absent(tmp_path):
    target = tmp_path / "home" / ".kube"
    dir_fd = open_dir_fd(target, create=True)
    try:
        assert target.is_dir()
        assert (target.stat().st_mode & 0o777) == 0o700
        assert read_via_fd(dir_fd, "config") is None
    finally:
        os.close(dir_fd)


@posix_only
def test_open_dir_fd_without_create_raises_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        open_dir_fd(tmp_path / "missing", create=False)


@posix_only
def test_open_dir_fd_refuses_a_symlinked_dir(tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir()
    link = tmp_path / ".kube"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(SecureFileError):
        open_dir_fd(link, create=False)


@posix_only
def test_read_via_fd_refuses_a_symlinked_file(tmp_path):
    target = tmp_path / "target"
    target.write_text("secret")
    (tmp_path / "config").symlink_to(target)
    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        with pytest.raises(SecureFileError):
            read_via_fd(dir_fd, "config")
    finally:
        os.close(dir_fd)


@posix_only
def test_read_via_fd_rejects_non_utf8_content(tmp_path):
    (tmp_path / "config").write_bytes(b"clusters: \xff\xfe")
    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        with pytest.raises(SecureFileError, match="not a UTF-8 text file"):
            read_via_fd(dir_fd, "config")
    finally:
        os.close(dir_fd)


@posix_only
def test_atomic_write_via_fd_new_file_is_private_and_existing_mode_is_kept(tmp_path):
    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        atomic_write_via_fd(dir_fd, "fresh", "a\n")
        assert (tmp_path / "fresh").read_text() == "a\n"
        assert stat.S_IMODE((tmp_path / "fresh").stat().st_mode) == 0o600

        (tmp_path / "loose").write_text("old\n")
        os.chmod(tmp_path / "loose", 0o644)
        atomic_write_via_fd(dir_fd, "loose", "new\n")
        assert (tmp_path / "loose").read_text() == "new\n"
        assert stat.S_IMODE((tmp_path / "loose").stat().st_mode) == 0o644
    finally:
        os.close(dir_fd)


@posix_only
def test_atomic_write_via_fd_keeps_temp_private_until_swap(tmp_path, monkeypatch):
    # Even when the target is 0644, the secret only ever sits in a 0600 temp file.
    (tmp_path / "config").write_text("old\n")
    os.chmod(tmp_path / "config", 0o644)
    modes_at_swap = []
    real_rename = os.rename

    def _spy_rename(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
        modes_at_swap.append(
            stat.S_IMODE(os.stat(src, dir_fd=src_dir_fd, follow_symlinks=False).st_mode)
        )
        return real_rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    monkeypatch.setattr(secure_file.os, "rename", _spy_rename)
    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        atomic_write_via_fd(dir_fd, "config", "new\n")
    finally:
        os.close(dir_fd)

    assert modes_at_swap == [0o600]


@posix_only
def test_atomic_write_via_fd_cleans_the_temp_on_failure(tmp_path, monkeypatch):
    (tmp_path / "config").write_text("old\n")

    def _boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(secure_file.os, "rename", _boom)
    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        with pytest.raises(OSError):
            atomic_write_via_fd(dir_fd, "config", "new\n")
    finally:
        os.close(dir_fd)

    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".plant.")] == []
    assert (tmp_path / "config").read_text() == "old\n"


@posix_only
def test_atomic_write_is_immune_to_a_dir_swap_after_open(tmp_path, monkeypatch):
    # TOCTOU: the dir is swapped for a symlink to an attacker dir right after the fd is
    # opened; the write must follow the fd to the original inode.
    home = tmp_path / "home"
    real_dir = home / ".kube"
    real_dir.mkdir(parents=True)
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    real_open = os.open
    state = {"swapped": False}

    def _swap_then_open(p, *args, **kwargs):
        fd = real_open(p, *args, **kwargs)
        if not state["swapped"] and os.path.basename(str(p)) == ".kube":
            state["swapped"] = True
            real_dir.rename(tmp_path / ".kube.real")
            os.symlink(attacker, real_dir, target_is_directory=True)
        return fd

    monkeypatch.setattr(secure_file.os, "open", _swap_then_open)
    dir_fd = open_dir_fd(real_dir, create=True)
    try:
        atomic_write_via_fd(dir_fd, "config", "planted\n")
    finally:
        os.close(dir_fd)

    assert (tmp_path / ".kube.real" / "config").read_text() == "planted\n"
    assert list(attacker.iterdir()) == []


@posix_only
def test_open_dir_fd_holds_an_exclusive_lock(tmp_path):
    import fcntl

    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        probe = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(probe)
    finally:
        os.close(dir_fd)


@posix_only
def test_unlink_via_fd_is_best_effort(tmp_path):
    (tmp_path / "config").write_text("x")
    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        unlink_via_fd(dir_fd, "config")
        unlink_via_fd(dir_fd, "config")  # already gone → no error
    finally:
        os.close(dir_fd)
    assert not (tmp_path / "config").exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX-only fail-closed guard")
def test_require_safe_backend_fails_closed_on_posix_without_fd_support(monkeypatch):
    monkeypatch.setattr(secure_file, "FD_HARDENED", False)
    with pytest.raises(SecureFileError):
        require_safe_backend()


# --- path-based fallback (used where dir fds are unavailable) ------------------------


def test_reject_symlinked_target_refuses_symlinked_parent_and_file(tmp_path):
    if sys.platform == "win32":
        pytest.skip("symlink creation needs privileges on Windows")
    real = tmp_path / "real"
    real.mkdir()
    link_dir = tmp_path / "linkdir"
    link_dir.symlink_to(real, target_is_directory=True)
    with pytest.raises(SecureFileError):
        reject_symlinked_target(link_dir / "config")

    (real / "target").write_text("x")
    (real / "config").symlink_to(real / "target")
    with pytest.raises(SecureFileError):
        reject_symlinked_target(real / "config")


def test_path_backend_round_trip_and_mode(tmp_path):
    path = tmp_path / "home" / ".kube" / "config"
    assert read_path(path) is None

    atomic_write_path(path, "a\n")
    assert read_path(path) == "a\n"
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        os.chmod(path, 0o644)
        atomic_write_path(path, "b\n")
        assert stat.S_IMODE(path.stat().st_mode) == 0o644
    assert read_path(path) == "b\n"
    assert [p.name for p in path.parent.iterdir() if p.name.startswith(".plant.")] == []


def test_read_path_rejects_non_utf8_content(tmp_path):
    path = tmp_path / "config"
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(SecureFileError, match="not a UTF-8 text file"):
        read_path(path)


def test_atomic_write_path_cleans_the_temp_on_failure(tmp_path, monkeypatch):
    path = tmp_path / "config"
    path.write_text("old\n")

    def _boom(*args, **kwargs):
        raise OSError("disk full")

    monkeypatch.setattr(secure_file.os, "replace", _boom)
    with pytest.raises(OSError):
        atomic_write_path(path, "new\n")

    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".plant.")] == []
    assert path.read_text() == "old\n"
    assert isinstance(Path(path), Path)
