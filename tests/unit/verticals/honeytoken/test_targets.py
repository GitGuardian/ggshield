import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from ggshield.verticals.honeytoken import targets as targets_mod
from ggshield.verticals.honeytoken.targets import (
    Target,
    _gid_for_uid,
    apply_perms_and_owner,
    machine_info_for,
    resolve_targets,
)


pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX target resolution"
)


def test_user_dir_target_uses_current_username(monkeypatch):
    monkeypatch.setattr(targets_mod, "_get_username", lambda: "alice")
    targets = resolve_targets(user=None, user_dir=Path("/tmp/ht"))
    assert len(targets) == 1
    assert targets[0].username == "alice"
    assert targets[0].home == Path("/tmp/ht")
    assert targets[0].uid is None


def test_user_dir_with_user_keeps_passwd_uid(monkeypatch):
    # --user-dir + an existing --user: keep the overridden home but resolve the uid so
    # a root run still chowns the decoy to that user.
    monkeypatch.setattr(
        "pwd.getpwnam",
        lambda name: SimpleNamespace(pw_dir="/home/bob", pw_uid=1001, pw_gid=1001),
    )
    (target,) = resolve_targets(user="bob", user_dir=Path("/tmp/ht"))
    assert target.username == "bob"
    assert target.home == Path("/tmp/ht")  # the overridden dir wins over passwd home
    assert target.uid == 1001


def test_user_dir_with_unknown_user_falls_back_to_no_uid(monkeypatch):
    # --user-dir + a --user absent from passwd (the testing/edge case): no failure,
    # uid stays None.
    def _raise(_name):
        raise KeyError

    monkeypatch.setattr("pwd.getpwnam", _raise)
    (target,) = resolve_targets(user="ghost", user_dir=Path("/tmp/ht"))
    assert target.username == "ghost"
    assert target.home == Path("/tmp/ht")
    assert target.uid is None


def test_user_target_resolves_via_passwd(monkeypatch):
    monkeypatch.setattr(
        "pwd.getpwnam",
        lambda name: SimpleNamespace(pw_dir="/home/bob", pw_uid=1001, pw_gid=1001),
    )
    (target,) = resolve_targets(user="bob", user_dir=None)
    assert target.username == "bob"
    assert target.home == Path("/home/bob")
    assert target.uid == 1001


def test_unknown_user_raises_lookup(monkeypatch):
    def _raise(_name):
        raise KeyError

    monkeypatch.setattr("pwd.getpwnam", _raise)
    with pytest.raises(LookupError):
        resolve_targets(user="ghost", user_dir=None)


def test_non_root_targets_current_user(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(targets_mod, "_get_username", lambda: "alice")
    monkeypatch.setattr(targets_mod, "get_user_home_dir", lambda: tmp_path)
    (target,) = resolve_targets(user=None, user_dir=None)
    assert target.username == "alice"
    assert target.home == tmp_path
    assert target.uid is None


def test_root_fans_out_to_user_homes(monkeypatch, tmp_path):
    alice_home = tmp_path / "alice"
    root_home = tmp_path / "root"
    for home in (alice_home, root_home):
        home.mkdir()

    entries = [
        SimpleNamespace(
            pw_name="alice",
            pw_dir=str(alice_home),
            pw_uid=1001,
            pw_gid=1001,
            pw_shell="/bin/bash",
        ),
        # System account: low uid, nologin, non-common home → filtered out.
        SimpleNamespace(
            pw_name="daemon",
            pw_dir="/var/empty-does-not-exist",
            pw_uid=1,
            pw_gid=1,
            pw_shell="/usr/sbin/nologin",
        ),
        SimpleNamespace(
            pw_name="root",
            pw_dir=str(root_home),
            pw_uid=0,
            pw_gid=0,
            pw_shell="/bin/sh",
        ),
    ]
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr("pwd.getpwall", lambda: entries)

    targets = resolve_targets(user=None, user_dir=None)
    by_name = {t.username: t for t in targets}
    assert set(by_name) == {"alice", "root"}  # daemon filtered out
    assert by_name["alice"].uid == 1001
    assert by_name["root"].uid == 0


def test_enumerate_dedups_same_home(monkeypatch, tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    entries = [
        SimpleNamespace(
            pw_name="alice",
            pw_dir=str(shared),
            pw_uid=1001,
            pw_gid=1001,
            pw_shell="/bin/bash",
        ),
        SimpleNamespace(
            pw_name="alias",
            pw_dir=str(shared),
            pw_uid=1002,
            pw_gid=1002,
            pw_shell="/bin/bash",
        ),
    ]
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr("pwd.getpwall", lambda: entries)
    targets = resolve_targets(user=None, user_dir=None)
    assert len(targets) == 1  # same realpath → deduped


def test_apply_perms_non_root_sets_mode(tmp_path):
    path = tmp_path / ".aws" / "credentials"
    path.parent.mkdir()
    path.write_text("x")
    apply_perms_and_owner(
        path, Target("alice", tmp_path, uid=None), running_as_root=False
    )
    assert (path.stat().st_mode & 0o777) == 0o600
    assert (path.parent.stat().st_mode & 0o777) == 0o700


def test_apply_perms_root_chowns(monkeypatch, tmp_path):
    path = tmp_path / ".aws" / "credentials"
    path.parent.mkdir()
    path.write_text("x")
    chowns = []
    monkeypatch.setattr(os, "chown", lambda p, u, g: chowns.append((str(p), u, g)))
    monkeypatch.setattr("pwd.getpwuid", lambda uid: SimpleNamespace(pw_gid=2002))
    apply_perms_and_owner(path, Target("bob", tmp_path, uid=1001), running_as_root=True)
    assert (str(path), 1001, 2002) in chowns
    assert (str(path.parent), 1001, 2002) in chowns


def test_gid_for_uid_unknown_returns_none(monkeypatch):
    def _raise(_uid):
        raise KeyError

    monkeypatch.setattr("pwd.getpwuid", _raise)
    assert _gid_for_uid(4242) is None


def test_machine_info_for_uses_shared_helpers(monkeypatch):
    monkeypatch.setattr(targets_mod, "_get_machine_id", lambda: "MACHINE-1")
    monkeypatch.setattr(targets_mod, "_get_hostname", lambda: "host-1")
    assert machine_info_for("alice") == {
        "machine_id": "MACHINE-1",
        "username": "alice",
        "hostname": "host-1",
    }
