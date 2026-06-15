import configparser
import os
import stat
import sys
from pathlib import Path

import pytest

from ggshield.verticals.honeytoken.aws_profile import (
    FD_HARDENED,
    ForceRefusal,
    PlacementError,
    RemoveOutcome,
    WriteOutcome,
    aws_path,
    remove_aws_profile,
    resolve_placement,
    write_aws_profile,
)
from ggshield.verticals.honeytoken.endpoint_deployments import (
    DeploymentMethod,
    HoneytokenCreds,
    PlacementConfig,
)


def _creds(access_id: str, secret: str) -> HoneytokenCreds:
    return HoneytokenCreds(access_token_id=access_id, secret_key=secret)


def _section(path: Path, name: str) -> dict:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(path)
    return dict(parser[name])


# --- aws_path / resolve_placement -------------------------------------------------


def test_aws_path_composes_under_dot_aws():
    assert aws_path(Path("/home/alice"), "credentials") == Path(
        "/home/alice/.aws/credentials"
    )
    assert aws_path(Path("/home/alice"), "credentials.back") == Path(
        "/home/alice/.aws/credentials.back"
    )


@pytest.mark.parametrize("bad", ["", ".", "..", "a/b", "a\\b"])
def test_aws_path_rejects_traversal_and_separators(bad):
    with pytest.raises(PlacementError):
        aws_path(Path("/home/alice"), bad)


def test_resolve_placement_credentials_has_no_prefix():
    path, section = resolve_placement(
        DeploymentMethod.AWS_CREDENTIALS,
        PlacementConfig(filename="credentials", profile_name="gg"),
        Path("/home/alice"),
    )
    assert path == Path("/home/alice/.aws/credentials")
    assert section == "gg"


def test_resolve_placement_config_profile_has_prefix():
    path, section = resolve_placement(
        DeploymentMethod.AWS_CONFIG_PROFILE,
        PlacementConfig(filename="config", profile_name="gg"),
        Path("/home/alice"),
    )
    assert path == Path("/home/alice/.aws/config")
    assert section == "profile gg"


def test_resolve_placement_unknown_method_raises():
    with pytest.raises(PlacementError):
        resolve_placement(
            DeploymentMethod.UNKNOWN,
            PlacementConfig(filename="x", profile_name="y"),
            Path("/home/alice"),
        )


# --- write_aws_profile ------------------------------------------------------------


def test_write_creates_when_absent(tmp_path):
    path = tmp_path / "credentials"
    outcome = write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert outcome is WriteOutcome.WROTE
    assert _section(path, "gg") == {
        "aws_access_key_id": "K1",
        "aws_secret_access_key": "S1",
    }


@pytest.mark.skipif(not FD_HARDENED, reason="needs dir fds / O_NOFOLLOW (POSIX)")
def test_write_creates_aws_dir_when_missing(tmp_path):
    """Planting into a home with no ``~/.aws`` creates it (private) and writes the profile."""
    path = tmp_path / "home" / ".aws" / "credentials"  # .aws does not exist yet
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert _section(path, "gg")["aws_access_key_id"] == "K1"
    assert path.parent.is_dir()
    assert (path.parent.stat().st_mode & 0o077) == 0  # no group/other access


def test_write_is_idempotent_for_same_key(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert (
        write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
        is WriteOutcome.ALREADY_CURRENT
    )


def test_write_refuses_drifted_secret_without_force(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    with pytest.raises(ForceRefusal):
        write_aws_profile(path, "gg", _creds("K1", "S2"), force=False)


def test_write_repairs_drifted_secret_with_force(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert (
        write_aws_profile(path, "gg", _creds("K1", "S2"), force=True)
        is WriteOutcome.WROTE
    )
    assert _section(path, "gg")["aws_secret_access_key"] == "S2"


def test_write_refuses_foreign_collision_without_force(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("OTHER", "X"), force=False)
    with pytest.raises(ForceRefusal):
        write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)


def test_write_preserves_other_profiles(tmp_path):
    path = tmp_path / "credentials"
    parser = configparser.ConfigParser(interpolation=None)
    parser["default"] = {"aws_access_key_id": "USER", "aws_secret_access_key": "MINE"}
    with open(path, "w") as handle:
        parser.write(handle)

    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert _section(path, "default") == {
        "aws_access_key_id": "USER",
        "aws_secret_access_key": "MINE",
    }
    assert _section(path, "gg")["aws_access_key_id"] == "K1"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file mode bits")
def test_write_sets_restrictive_permissions(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert (path.stat().st_mode & 0o777) == 0o600


# --- remove_aws_profile -----------------------------------------------------------


def test_remove_absent_file(tmp_path):
    assert (
        remove_aws_profile(tmp_path / "credentials", "gg", None)
        is RemoveOutcome.ALREADY_ABSENT
    )


def test_remove_absent_profile(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "other", _creds("K1", "S1"), force=False)
    assert remove_aws_profile(path, "gg", None) is RemoveOutcome.ALREADY_ABSENT


def test_remove_keeps_other_profiles(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "default", _creds("USER", "MINE"), force=False)
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert remove_aws_profile(path, "gg", None) is RemoveOutcome.REMOVED
    assert path.exists()
    assert _section(path, "default")["aws_access_key_id"] == "USER"


def test_remove_deletes_now_empty_file(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert remove_aws_profile(path, "gg", None) is RemoveOutcome.REMOVED
    assert not path.exists()


def test_remove_when_key_matches(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    assert remove_aws_profile(path, "gg", "K1") is RemoveOutcome.REMOVED
    assert not path.exists()


def test_write_on_malformed_file_raises_placement_error(tmp_path):
    path = tmp_path / "credentials"
    path.write_text("[\nnot an ini file at all")
    with pytest.raises(PlacementError):
        write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)


def test_remove_on_malformed_file_raises_placement_error(tmp_path):
    path = tmp_path / "credentials"
    path.write_text("garbage = without [ header")
    with pytest.raises(PlacementError):
        remove_aws_profile(path, "gg", None)


def test_remove_keeps_foreign_key(tmp_path):
    path = tmp_path / "credentials"
    write_aws_profile(path, "gg", _creds("OTHER", "X"), force=False)
    assert remove_aws_profile(path, "gg", "K1") is RemoveOutcome.FOREIGN_KEPT
    # Section left untouched.
    assert _section(path, "gg")["aws_access_key_id"] == "OTHER"


# --- comment / formatting preservation --------------------------------------------
#
# Planting only touches our own profile; comments, blank lines and other profiles
# stay intact.


_FILE_WITH_COMMENTS = """\
# Personal AWS credentials -- DO NOT COMMIT
[default]
aws_access_key_id = USER
aws_secret_access_key = MINE

# work account, see https://wiki.internal/aws
[work]
aws_access_key_id = WK
aws_secret_access_key = WS
"""


def test_write_preserves_existing_comments(tmp_path):
    path = tmp_path / "credentials"
    path.write_text(_FILE_WITH_COMMENTS)

    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)

    content = path.read_text()
    assert "# Personal AWS credentials -- DO NOT COMMIT" in content
    assert "# work account, see https://wiki.internal/aws" in content
    # And our profile must of course be present.
    assert _section(path, "gg")["aws_access_key_id"] == "K1"


def test_write_leaves_other_sections_byte_for_byte(tmp_path):
    """Planting our profile must not reformat or reorder the rest of the file: the
    original content should remain a prefix of the result, with only our section
    appended."""
    path = tmp_path / "credentials"
    path.write_text(_FILE_WITH_COMMENTS)

    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)

    content = path.read_text()
    assert content.startswith(_FILE_WITH_COMMENTS)


def test_write_appends_cleanly_to_file_without_trailing_newline(tmp_path):
    """A source file with no final newline must still get our profile as a real,
    separate section -- not glued onto the last line (``...= MINE[gg]``), which would
    silently drop our profile (or raise on a duplicate option)."""
    path = tmp_path / "credentials"
    path.write_bytes(
        b"# kept\n[default]\naws_access_key_id = USER\naws_secret_access_key = MINE"
    )  # note: no trailing newline

    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)

    assert _section(path, "gg")["aws_access_key_id"] == "K1"
    assert _section(path, "default")["aws_access_key_id"] == "USER"
    content = path.read_text()
    assert "# kept" in content
    assert content.endswith("\n")


def test_remove_preserves_comments_on_other_profiles(tmp_path):
    path = tmp_path / "credentials"
    path.write_text(_FILE_WITH_COMMENTS)
    # Plant then remove our profile; the user's commented profiles must survive intact.
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    remove_aws_profile(path, "gg", "K1")

    content = path.read_text()
    assert "# Personal AWS credentials -- DO NOT COMMIT" in content
    assert "# work account, see https://wiki.internal/aws" in content


def test_remove_keeps_file_when_only_comments_remain(tmp_path):
    """If removing our profile leaves no other section but the user still has comments,
    keep the file (with the comments) rather than deleting it as an empty stub."""
    path = tmp_path / "credentials"
    path.write_text(
        "# keep me\n[gg]\naws_access_key_id = K1\naws_secret_access_key = S1\n"
    )

    assert remove_aws_profile(path, "gg", None) is RemoveOutcome.REMOVED
    assert path.exists()
    content = path.read_text()
    assert "# keep me" in content
    assert "[gg]" not in content


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file mode bits")
def test_write_preserves_existing_file_mode(tmp_path):
    """A normal write to an existing file keeps the user's permission bits (here 0640)
    rather than forcing 0600 -- same 'don't disturb the user's file' spirit as comments.
    """
    path = tmp_path / "credentials"
    path.write_text(
        "[default]\naws_access_key_id = USER\naws_secret_access_key = MINE\n"
    )
    os.chmod(path, 0o640)

    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)

    assert (path.stat().st_mode & 0o777) == 0o640
    assert _section(path, "gg")["aws_access_key_id"] == "K1"


def test_write_does_not_mix_newlines_on_crlf_file(tmp_path):
    """A CRLF (Windows-authored) file must not come back with mixed line endings: the
    result must use a single consistent convention. (We don't assert which one -- the
    text-mode write resolves to the platform's newline -- only that it isn't mixed.)"""
    path = tmp_path / "credentials"
    path.write_bytes(
        b"# windows-authored creds\r\n"
        b"[default]\r\n"
        b"aws_access_key_id = USER\r\n"
        b"aws_secret_access_key = MINE\r\n"
    )

    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)

    raw = path.read_bytes()
    # No lone LF that isn't part of a CRLF (would signal a CRLF/LF mix).
    assert b"\r\n" not in raw or raw.replace(b"\r\n", b"").count(b"\n") == 0
    assert b"# windows-authored creds" in raw


def test_remove_keeps_comments_only_remainder(tmp_path):
    """A {comments + only our section} file must survive removal with comments intact:
    `sections()` is empty after removing ours, but the document isn't — so don't unlink.
    """
    path = tmp_path / "credentials"
    path.write_text("# keep me -- personal note\n")
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)

    assert remove_aws_profile(path, "gg", "K1") is RemoveOutcome.REMOVED
    assert path.exists()
    content = path.read_text()
    assert "# keep me -- personal note" in content
    assert "[gg]" not in content


# --- symlink hardening (root fan-out privilege-escalation guard) ------------------
#
# As root in the fleet fan-out, following a symlinked `.aws` (or credentials file)
# would let a user redirect the write/chmod/chown outside their home. We reject.


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_write_rejects_symlinked_aws_dir(tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    (home / ".aws").symlink_to(real, target_is_directory=True)
    path = home / ".aws" / "credentials"

    with pytest.raises(PlacementError):
        write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    # Nothing was written through the link.
    assert list(real.iterdir()) == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_remove_rejects_symlinked_aws_dir(tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    (home / ".aws").symlink_to(real, target_is_directory=True)
    path = home / ".aws" / "credentials"

    with pytest.raises(PlacementError):
        remove_aws_profile(path, "gg", None)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks")
def test_write_rejects_symlinked_credentials_file(tmp_path):
    target = tmp_path / "target-creds"
    target.write_text(
        "[default]\naws_access_key_id = USER\naws_secret_access_key = MINE\n"
    )
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir(mode=0o700)
    path = aws_dir / "credentials"
    path.symlink_to(target)

    with pytest.raises(PlacementError):
        write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)
    # The link target was not modified through the symlink.
    assert "gg" not in target.read_text()


@pytest.mark.skipif(not FD_HARDENED, reason="needs dir fds / O_NOFOLLOW (POSIX)")
def test_write_keeps_temp_private_until_swap(tmp_path, monkeypatch):
    """Even when the existing file is permissive (0644), the temp stays 0600 until the
    rename swap — the secret never sits in a group/world-readable temp."""
    from ggshield.verticals.honeytoken import aws_profile

    path = tmp_path / "credentials"
    path.write_text(
        "[default]\naws_access_key_id = USER\naws_secret_access_key = MINE\n"
    )
    os.chmod(path, 0o644)

    modes_at_swap = []
    real_rename = os.rename

    def _spy_rename(src, dst, *, src_dir_fd=None, dst_dir_fd=None):
        modes_at_swap.append(
            stat.S_IMODE(os.stat(src, dir_fd=src_dir_fd, follow_symlinks=False).st_mode)
        )
        return real_rename(src, dst, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    monkeypatch.setattr(aws_profile.os, "rename", _spy_rename)
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)

    assert modes_at_swap == [0o600]  # temp private at swap time
    assert (path.stat().st_mode & 0o777) == 0o644  # final mode preserved


@pytest.mark.skipif(not FD_HARDENED, reason="needs dir fds / O_NOFOLLOW (POSIX)")
def test_write_is_immune_to_aws_dir_swap_after_open(tmp_path, monkeypatch):
    """TOCTOU: swap `.aws` for a symlink to an attacker dir right after the dir fd is
    opened. The write must follow the fd to the original real dir, never the attacker's.
    """
    from ggshield.verticals.honeytoken import aws_profile

    home = tmp_path / "home"
    real_aws = home / ".aws"
    real_aws.mkdir(parents=True)
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    path = real_aws / "credentials"

    real_open = os.open
    state = {"swapped": False}

    def _swap_then_open(p, *args, **kwargs):
        fd = real_open(p, *args, **kwargs)
        if not state["swapped"] and os.path.basename(str(p)) == ".aws":
            state["swapped"] = True
            real_aws.rename(tmp_path / ".aws.real")
            os.symlink(attacker, real_aws, target_is_directory=True)
        return fd

    monkeypatch.setattr(aws_profile.os, "open", _swap_then_open)
    write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)

    # Landed in the original (moved-aside) real dir via the fd — never the attacker's.
    assert (tmp_path / ".aws.real" / "credentials").exists()
    assert list(attacker.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX-only fail-closed guard")
def test_write_fails_closed_on_posix_without_fd_support(tmp_path, monkeypatch):
    """On POSIX we refuse rather than fall back to TOCTOU-prone path operations when the
    no-follow / dir-fd backend isn't available."""
    from ggshield.verticals.honeytoken import aws_profile

    monkeypatch.setattr(aws_profile, "FD_HARDENED", False)
    with pytest.raises(PlacementError):
        write_aws_profile(
            tmp_path / "credentials", "gg", _creds("K1", "S1"), force=False
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX-only fail-closed guard")
def test_remove_fails_closed_on_posix_without_fd_support(tmp_path, monkeypatch):
    from ggshield.verticals.honeytoken import aws_profile

    path = tmp_path / "credentials"
    path.write_text("[gg]\naws_access_key_id = K1\naws_secret_access_key = S1\n")
    monkeypatch.setattr(aws_profile, "FD_HARDENED", False)
    with pytest.raises(PlacementError):
        remove_aws_profile(path, "gg", None)


@pytest.mark.skipif(not FD_HARDENED, reason="needs dir fds / O_NOFOLLOW (POSIX)")
def test_remove_when_aws_dir_absent(tmp_path):
    """remove on a home whose ``.aws`` doesn't exist yet → nothing to do."""
    path = tmp_path / "home" / ".aws" / "credentials"  # .aws never created
    assert remove_aws_profile(path, "gg", None) is RemoveOutcome.ALREADY_ABSENT


def test_write_refuses_section_missing_a_key_without_force(tmp_path):
    """An existing profile that carries our access key but is missing the secret is a
    mismatch (not ALREADY_CURRENT) → refuse without --force."""
    path = tmp_path / ".aws" / "credentials"
    path.parent.mkdir(parents=True)
    path.write_text("[gg]\naws_access_key_id = K1\n")  # no secret line

    with pytest.raises(ForceRefusal):
        write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)


@pytest.mark.skipif(not FD_HARDENED, reason="needs dir fds / O_NOFOLLOW (POSIX)")
def test_write_cleans_up_temp_on_failure(tmp_path, monkeypatch):
    """If serializing the parser fails mid-write, the temp file is unlinked (no leak in
    ``.aws``) and the original file is left intact."""
    from configupdater import ConfigUpdater

    path = tmp_path / ".aws" / "credentials"
    path.parent.mkdir(parents=True)
    original = "[default]\naws_access_key_id = USER\naws_secret_access_key = MINE\n"
    path.write_text(original)

    def boom(self, *args, **kwargs):
        raise RuntimeError("disk full")

    monkeypatch.setattr(ConfigUpdater, "write", boom)

    with pytest.raises(RuntimeError):
        write_aws_profile(path, "gg", _creds("K1", "S1"), force=False)

    leftover = [p.name for p in path.parent.iterdir() if p.name.startswith(".plant.")]
    assert leftover == []
    assert path.read_text() == original


# --- concurrency: advisory lock over the read-modify-write window ------------------


@pytest.mark.skipif(not FD_HARDENED, reason="POSIX advisory lock")
def test_open_aws_dir_fd_holds_exclusive_lock(tmp_path):
    """The dir fd carries an exclusive advisory lock, so a second acquirer is blocked."""
    import fcntl

    from ggshield.verticals.honeytoken.aws_profile import open_aws_dir_fd

    aws = tmp_path / ".aws"
    aws.mkdir()
    dir_fd = open_aws_dir_fd(aws, create=False)
    try:
        probe = os.open(aws, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(probe)
    finally:
        os.close(dir_fd)  # releases the lock


@pytest.mark.skipif(not FD_HARDENED, reason="POSIX advisory lock")
def test_concurrent_plants_do_not_lose_a_profile(tmp_path, monkeypatch):
    """Two plant invocations racing on the same file must not lose an update: the lock
    serializes their read-modify-write so both profiles survive (a missing lock would
    let the second rename clobber the first)."""
    import threading
    import time

    from ggshield.verticals.honeytoken import aws_profile

    path = tmp_path / ".aws" / "credentials"
    path.parent.mkdir(parents=True)

    # Widen the RMW window so an unlocked race would reliably drop one update.
    real_write = aws_profile._atomic_write_via_fd

    def slow_write(*args, **kwargs):
        time.sleep(0.3)
        return real_write(*args, **kwargs)

    monkeypatch.setattr(aws_profile, "_atomic_write_via_fd", slow_write)

    start = threading.Barrier(2)
    errors = []

    def plant(name):
        try:
            start.wait()
            write_aws_profile(path, name, _creds(name, name + "-secret"), force=False)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=plant, args=(n,)) for n in ("gg1", "gg2")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert _section(path, "gg1")["aws_access_key_id"] == "gg1"
    assert _section(path, "gg2")["aws_access_key_id"] == "gg2"
