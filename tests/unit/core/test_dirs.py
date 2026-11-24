"""Machine-wide dirs: one fixed write location per OS, and a read list made of
that location plus every XDG entry (see ggshield/core/dirs.py)."""

import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Callable, Dict, List, Optional, Tuple

import pytest

import ggshield.core.dirs as dirs_mod
from ggshield.core.dirs import (
    get_plugin_read_dirs,
    get_system_config_dir,
    get_system_config_dirs,
    get_system_data_dir,
    get_system_data_dirs,
    get_system_plugins_dir,
    get_system_plugins_dirs,
)


linux_only = pytest.mark.skipif(
    sys.platform != "linux", reason="exercises platformdirs' XDG handling"
)


@pytest.fixture
def xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[[str], Path]:
    """Hermetic Linux layout: fixed dirs and XDG entries live under tmp_path.

    Returns a function creating a ``<tmp>/<name>`` XDG entry holding a ggshield
    dir. Tmp dirs cannot satisfy the real safety check (/tmp is world-writable,
    CI may run as root), so it only requires the dir to exist."""
    monkeypatch.delenv("GG_SYSTEM_DATA_DIR", raising=False)
    monkeypatch.delenv("GG_SYSTEM_CONFIG_DIR", raising=False)
    monkeypatch.setattr(dirs_mod, "_LINUX_SYSTEM_DATA_DIR", tmp_path / "fixed-data")
    monkeypatch.setattr(dirs_mod, "_LINUX_SYSTEM_CONFIG_DIR", tmp_path / "fixed-conf")
    monkeypatch.setattr(dirs_mod, "_is_safe_system_dir", lambda p: p.is_dir())

    def make_entry(name: str) -> Path:
        entry = tmp_path / name
        (entry / "ggshield").mkdir(parents=True)
        return entry

    return make_entry


def _set_xdg(
    monkeypatch: pytest.MonkeyPatch, data: List[Path], config: List[Path]
) -> None:
    monkeypatch.setenv("XDG_DATA_DIRS", os.pathsep.join(map(str, data)))
    monkeypatch.setenv("XDG_CONFIG_DIRS", os.pathsep.join(map(str, config)))


def test_fixed_write_dirs_per_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GG_SYSTEM_DATA_DIR", raising=False)
    monkeypatch.delenv("GG_SYSTEM_CONFIG_DIR", raising=False)
    if sys.platform == "darwin":
        expected_data = expected_config = Path("/Library/Application Support/ggshield")
    elif sys.platform == "win32":
        pytest.skip("Windows uses a ProgramData path")
    else:
        expected_data = Path("/usr/local/share/ggshield")
        expected_config = Path("/etc/xdg/ggshield")

    assert get_system_data_dir() == expected_data
    assert get_system_config_dir() == expected_config


@linux_only
@pytest.mark.parametrize("gnome_first", [False, True])
def test_write_dirs_ignore_xdg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gnome_first: bool
) -> None:
    monkeypatch.delenv("GG_SYSTEM_DATA_DIR", raising=False)
    monkeypatch.delenv("GG_SYSTEM_CONFIG_DIR", raising=False)
    if gnome_first:
        _set_xdg(
            monkeypatch,
            [tmp_path / "gnome", tmp_path / "share"],
            [tmp_path / "xdg-ubuntu", tmp_path / "xdg"],
        )
    else:
        monkeypatch.delenv("XDG_DATA_DIRS", raising=False)
        monkeypatch.delenv("XDG_CONFIG_DIRS", raising=False)

    assert get_system_data_dir() == Path("/usr/local/share/ggshield")
    assert get_system_config_dir() == Path("/etc/xdg/ggshield")
    assert get_system_plugins_dir() == Path("/usr/local/share/ggshield/plugins")


def test_overrides_are_the_only_system_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("GG_SYSTEM_CONFIG_DIR", str(tmp_path / "conf"))

    assert get_system_data_dirs() == [tmp_path / "data"]
    assert get_system_config_dirs() == [tmp_path / "conf"]
    assert get_system_plugins_dirs() == [tmp_path / "data" / "plugins"]


@pytest.mark.parametrize("root", [True, False])
def test_macos_root_reads_only_fixed_system_dirs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root: bool
) -> None:
    fixed = tmp_path / "fixed"
    secondary = tmp_path / "secondary"
    monkeypatch.setattr(dirs_mod.sys, "platform", "darwin")
    monkeypatch.setattr(dirs_mod, "is_root", lambda: root)
    monkeypatch.setattr(dirs_mod, "_MACOS_SYSTEM_DIR", fixed)
    monkeypatch.setattr(dirs_mod, "_is_safe_system_dir", lambda p: True)
    monkeypatch.delenv("GG_SYSTEM_DATA_DIR", raising=False)
    monkeypatch.delenv("GG_SYSTEM_CONFIG_DIR", raising=False)
    _set_xdg(monkeypatch, [secondary], [secondary])

    expected = [fixed] if root else [fixed, secondary / "ggshield"]
    assert get_system_data_dirs() == expected
    assert get_system_config_dirs() == expected


@linux_only
def test_read_dirs_follow_xdg_order_fixed_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, xdg: Callable[[str], Path]
) -> None:
    gnome, local, usr = xdg("gnome"), xdg("local"), xdg("usr")
    conf_a, conf_b = xdg("conf-a"), xdg("conf-b")
    _set_xdg(monkeypatch, [gnome, local, usr, local], [conf_a, conf_b, conf_a])

    assert get_system_data_dirs() == [
        tmp_path / "fixed-data",
        gnome / "ggshield",
        local / "ggshield",
        usr / "ggshield",
    ]
    assert get_system_config_dirs() == [
        tmp_path / "fixed-conf",
        conf_a / "ggshield",
        conf_b / "ggshield",
    ]


@linux_only
def test_read_dirs_dedupe_entry_equal_to_fixed_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, xdg: Callable[[str], Path]
) -> None:
    fixed_entry = tmp_path / "fixed-entry"
    (fixed_entry / "ggshield").mkdir(parents=True)
    monkeypatch.setattr(dirs_mod, "_LINUX_SYSTEM_DATA_DIR", fixed_entry / "ggshield")
    other = xdg("other")
    _set_xdg(monkeypatch, [other, fixed_entry], [])

    assert get_system_data_dirs() == [fixed_entry / "ggshield", other / "ggshield"]


@linux_only
def test_read_dirs_ignore_empty_relative_and_blank_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, xdg: Callable[[str], Path]
) -> None:
    good = xdg("good")
    values = os.pathsep.join(["", "relative/dir", "  ", f"  {good}  ", "  "])
    monkeypatch.setenv("XDG_DATA_DIRS", values)
    monkeypatch.setenv("XDG_CONFIG_DIRS", values)

    def unexpected_platformdirs_call(**kwargs):
        pytest.fail("Explicit XDG entries should bypass platformdirs")

    monkeypatch.setattr(dirs_mod, "site_data_dir", unexpected_platformdirs_call)
    monkeypatch.setattr(dirs_mod, "site_config_dir", unexpected_platformdirs_call)

    assert get_system_data_dirs() == [tmp_path / "fixed-data", good / "ggshield"]
    assert get_system_config_dirs() == [tmp_path / "fixed-conf", good / "ggshield"]


@linux_only
@pytest.mark.parametrize("value", [None, "  "])
def test_read_dirs_use_spec_defaults_when_xdg_unset_or_blank(
    monkeypatch: pytest.MonkeyPatch, xdg: Callable[[str], Path], value: Optional[str]
) -> None:
    for name in ("XDG_DATA_DIRS", "XDG_CONFIG_DIRS"):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    monkeypatch.setattr(dirs_mod, "_is_safe_system_dir", lambda p: True)
    monkeypatch.setattr(dirs_mod, "_LINUX_SYSTEM_DATA_DIR", Path("/fixed/ggshield"))
    monkeypatch.setattr(dirs_mod, "_LINUX_SYSTEM_CONFIG_DIR", Path("/fixed-c/ggshield"))

    assert get_system_data_dirs() == [
        Path("/fixed/ggshield"),
        Path("/usr/local/share/ggshield"),
        Path("/usr/share/ggshield"),
    ]
    assert get_system_config_dirs() == [
        Path("/fixed-c/ggshield"),
        Path("/etc/xdg/ggshield"),
    ]


@linux_only
def test_unsafe_and_missing_entries_are_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, xdg: Callable[[str], Path]
) -> None:
    safe, unsafe = xdg("good"), xdg("bad")
    missing = tmp_path / "missing"
    monkeypatch.setattr(
        dirs_mod,
        "_is_safe_system_dir",
        lambda p: "bad" not in p.parts[-2:] and p.exists(),
    )
    _set_xdg(monkeypatch, [unsafe, missing, safe], [unsafe, safe])

    assert get_system_data_dirs() == [tmp_path / "fixed-data", safe / "ggshield"]
    assert get_system_config_dirs() == [tmp_path / "fixed-conf", safe / "ggshield"]


@linux_only
def test_plugins_dirs_require_safe_plugins_subdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, xdg: Callable[[str], Path]
) -> None:
    safe, unsafe, missing = xdg("safe"), xdg("unsafe"), xdg("missing")
    unsafe_plugins = unsafe / "ggshield" / "plugins"
    unsafe_plugins.mkdir()
    (safe / "ggshield" / "plugins").mkdir()
    monkeypatch.setattr(dirs_mod, "_is_safe_system_dir", lambda p: p != unsafe_plugins)
    _set_xdg(monkeypatch, [unsafe, missing, safe], [])

    # The fixed dir is the write location: always listed, even when absent.
    assert get_system_plugins_dirs() == [
        tmp_path / "fixed-data" / "plugins",
        missing / "ggshield" / "plugins",
        safe / "ggshield" / "plugins",
    ]


@pytest.mark.parametrize("root", [True, False])
@linux_only
def test_plugin_read_dirs_precedence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    xdg: Callable[[str], Path],
    root: bool,
) -> None:
    secondary = xdg("secondary")
    (secondary / "ggshield" / "plugins").mkdir()
    _set_xdg(monkeypatch, [secondary], [])
    monkeypatch.setenv("GG_DATA_DIR", str(tmp_path / "user-data"))
    monkeypatch.setattr(dirs_mod, "is_root", lambda: root)

    user = tmp_path / "user-data" / "plugins"
    system = [tmp_path / "fixed-data" / "plugins", secondary / "ggshield" / "plugins"]
    read_dirs, secondary_dirs = get_plugin_read_dirs()
    assert read_dirs == ([*system, user] if root else [user, *system])
    assert secondary_dirs == {system[1]}


@linux_only
def test_plugin_read_dirs_dedupe_user_dir_shared_with_system(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, xdg: Callable[[str], Path]
) -> None:
    monkeypatch.setenv("GG_DATA_DIR", str(tmp_path / "fixed-data"))
    monkeypatch.setattr(dirs_mod, "is_root", lambda: False)
    _set_xdg(monkeypatch, [tmp_path / "none"], [])

    assert get_plugin_read_dirs() == ([tmp_path / "fixed-data" / "plugins"], set())


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX ownership and modes")
class TestIsSafeSystemDir:
    ROOT_DIR = (0, 0o40755)

    @pytest.fixture
    def directory_modes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> Dict[Path, Tuple[int, int]]:
        """Simulate trusted ancestors above tmp_path and default to root ownership."""
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        modes: Dict[Path, Tuple[int, int]] = {}
        lstat = Path.lstat

        def get_stat(path: Path) -> SimpleNamespace:
            if path.is_relative_to(tmp_path):
                uid, mode = modes.get(path, (0, lstat(path).st_mode))
            else:
                uid, mode = self.ROOT_DIR
            return SimpleNamespace(st_uid=uid, st_mode=mode)

        monkeypatch.setattr(Path, "lstat", get_stat)
        return modes

    @pytest.mark.parametrize(
        "owner, mode, safe",
        [
            (0, 0o40755, True),
            (1000, 0o40755, True),
            (4242, 0o40755, False),
            (0, 0o40775, False),
            (0, 0o40757, False),
            (0, 0o41777, False),
        ],
    )
    def test_directory_permissions(
        self,
        tmp_path: Path,
        directory_modes: Dict[Path, Tuple[int, int]],
        owner: int,
        mode: int,
        safe: bool,
    ) -> None:
        directory_modes[tmp_path] = (owner, mode)
        assert dirs_mod._is_safe_system_dir(tmp_path) is safe

    def test_writable_ancestor_of_symlink_is_unsafe(
        self, tmp_path: Path, directory_modes: Dict[Path, Tuple[int, int]]
    ) -> None:
        target = tmp_path / "target"
        target.mkdir()
        parent = tmp_path / "parent"
        parent.mkdir()
        link = parent / "link"
        link.symlink_to(target, target_is_directory=True)
        assert dirs_mod._is_safe_system_dir(link)

        directory_modes[parent] = (0, 0o40777)
        assert not dirs_mod._is_safe_system_dir(link)

    def test_missing_path_is_unsafe(self, tmp_path: Path) -> None:
        assert not dirs_mod._is_safe_system_dir(tmp_path / "nope")
