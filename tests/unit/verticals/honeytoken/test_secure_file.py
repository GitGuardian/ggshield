import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

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
    unlink_path,
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
    if os.name == "posix":
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


# --- size cap (root fan-out DoS) ------------------------------------------------------


@posix_only
def test_read_via_fd_refuses_an_oversized_file(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_file, "MAX_FILE_SIZE", 16)
    (tmp_path / "config").write_text("x" * 17)
    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        with pytest.raises(SecureFileError, match="larger than the 16 byte limit"):
            read_via_fd(dir_fd, "config")
        (tmp_path / "small").write_text("x" * 16)
        assert read_via_fd(dir_fd, "small") == "x" * 16
    finally:
        os.close(dir_fd)


def test_read_path_refuses_an_oversized_file(tmp_path, monkeypatch):
    monkeypatch.setattr(secure_file, "MAX_FILE_SIZE", 16)
    path = tmp_path / "config"
    path.write_text("x" * 17)
    with pytest.raises(SecureFileError, match="larger than the 16 byte limit"):
        read_path(path)


# --- non-regular files: a FIFO must not hang the (root, lock-holding) run ----------------


@posix_only
def test_read_via_fd_refuses_a_fifo_without_blocking(tmp_path):
    os.mkfifo(tmp_path / "config")
    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        with pytest.raises(SecureFileError, match="not a regular file"):
            read_via_fd(dir_fd, "config")  # would block forever without O_NONBLOCK
    finally:
        os.close(dir_fd)


@posix_only
def test_read_via_fd_refuses_a_directory(tmp_path):
    (tmp_path / "config").mkdir()
    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        with pytest.raises(SecureFileError, match="not a regular file"):
            read_via_fd(dir_fd, "config")
    finally:
        os.close(dir_fd)


def test_read_path_refuses_a_directory(tmp_path):
    (tmp_path / "config").mkdir()
    with pytest.raises(SecureFileError, match="not a regular file"):
        read_path(tmp_path / "config")


# --- review round 3: the published name is never reopened ----------------------------


@posix_only
def test_read_via_fd_refuses_a_hardlinked_file(tmp_path):
    # S_ISREG alone lets a hardlink through. As root the fan-out would read a file the
    # directory's owner cannot open, then hand the content back in the copy it chowns
    # to them.
    secret = tmp_path / "elsewhere"
    secret.write_text("root only\n")
    os.link(secret, tmp_path / "config")

    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        with pytest.raises(SecureFileError, match="hard links"):
            read_via_fd(dir_fd, "config")
    finally:
        os.close(dir_fd)


@posix_only
def test_atomic_write_via_fd_never_opens_the_published_name(tmp_path, monkeypatch):
    # The mode/owner fix-up must ride the fd we already hold. Opening the name again
    # after the rename would let the dir's owner swap in a FIFO (which blocks the
    # lock-holding root run) or a hardlink (which redirects the privileged chmod).
    (tmp_path / "config").write_text("old\n")
    os.chmod(tmp_path / "config", 0o644)

    renamed = []
    reopened = []
    real_open = secure_file.os.open
    real_rename = secure_file.os.rename

    def _spy_rename(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
        renamed.append(dst)
        return real_rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    def _spy_open(path, *args, **kwargs):
        if renamed and path == "config":
            reopened.append(path)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(secure_file.os, "rename", _spy_rename)
    monkeypatch.setattr(secure_file.os, "open", _spy_open)
    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        atomic_write_via_fd(dir_fd, "config", "new\n")
    finally:
        os.close(dir_fd)

    assert renamed == ["config"]
    assert reopened == []
    # The user's mode still comes back, applied through the retained fd.
    assert stat.S_IMODE(os.stat(tmp_path / "config").st_mode) == 0o644


@posix_only
def test_atomic_write_via_fd_chowns_before_the_rename(tmp_path, monkeypatch):
    # A crash between the rename and a later chown would leave the target locked out of
    # their own config, so ownership is applied while the file is still the temp.
    (tmp_path / "config").write_text("old\n")
    order = []
    real_rename = secure_file.os.rename

    def _spy_rename(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
        order.append("rename")
        return real_rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    monkeypatch.setattr(secure_file.os, "rename", _spy_rename)
    monkeypatch.setattr(
        secure_file.os, "fchown", lambda fd, uid, gid: order.append(("chown", uid, gid))
    )
    monkeypatch.setattr("pwd.getpwuid", lambda uid: SimpleNamespace(pw_gid=2002))

    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        atomic_write_via_fd(dir_fd, "config", "new\n", secure_file.Ownership(uid=1001))
    finally:
        os.close(dir_fd)

    assert order == [("chown", 1001, 2002), "rename"]


@posix_only
def test_ownership_without_a_uid_falls_back_to_the_directory_owner(tmp_path):
    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        uid, _gid = secure_file.Ownership(uid=None).resolve(dir_fd)
    finally:
        os.close(dir_fd)

    assert uid == os.stat(tmp_path).st_uid


@posix_only
def test_unlink_via_fd_reports_a_removal_the_filesystem_refused(tmp_path, monkeypatch):
    # Passing a refused unlink off as success makes the server retire the delete while
    # the decoy is still on disk.
    (tmp_path / "config").write_text("x\n")

    def _refuse(*args, **kwargs):
        raise PermissionError("EROFS")

    monkeypatch.setattr(secure_file.os, "unlink", _refuse)
    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        with pytest.raises(SecureFileError, match="could not remove"):
            unlink_via_fd(dir_fd, "config")
    finally:
        os.close(dir_fd)


@posix_only
def test_unlink_via_fd_treats_an_absent_file_as_done(tmp_path):
    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        unlink_via_fd(dir_fd, "not-there")  # no raise
    finally:
        os.close(dir_fd)


def test_unlink_path_reports_a_removal_the_filesystem_refused(tmp_path, monkeypatch):
    # The path backend (Windows) gets the same guarantee. Patch the method itself:
    # before 3.11 pathlib reaches os.unlink through an accessor bound at import.
    target = tmp_path / "config"
    target.write_text("x\n")

    def _refuse(self, *args, **kwargs):
        raise PermissionError("EACCES")

    monkeypatch.setattr(Path, "unlink", _refuse)
    with pytest.raises(SecureFileError, match="could not remove"):
        unlink_path(target)


def test_unlink_path_treats_an_absent_file_as_done(tmp_path):
    unlink_path(tmp_path / "not-there")  # no raise


@posix_only
def test_a_filesystem_that_refuses_to_fsync_a_directory_still_writes(
    tmp_path, monkeypatch
):
    # Some filesystems reject fsync on a directory. The rename already made the data
    # durable, so that must not fail the placement.
    (tmp_path / "config").write_text("old\n")
    real_fsync = secure_file.os.fsync

    def _refuse_on_dirs(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("EINVAL")
        return real_fsync(fd)

    monkeypatch.setattr(secure_file.os, "fsync", _refuse_on_dirs)
    dir_fd = open_dir_fd(tmp_path, create=False)
    try:
        atomic_write_via_fd(dir_fd, "config", "new\n")
    finally:
        os.close(dir_fd)

    assert (tmp_path / "config").read_text() == "new\n"
