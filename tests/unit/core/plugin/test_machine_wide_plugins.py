"""Machine-wide (transparent cross-user) plugin support.

Privilege decides where install/enable land (root → system, user → per-user);
reads merge both layers. Driven here via GG_*_DIR overrides + a monkeypatched
is_root so it runs without actually being root.
"""

from __future__ import annotations

import json
import os
import sys
import textwrap
import uuid
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator, Sequence
from unittest.mock import Mock

import pytest

import ggshield.core.config.enterprise_config as ec_mod
import ggshield.core.dirs as dirs_mod
import ggshield.core.plugin.downloader as dl_mod
from ggshield.__main__ import cli
from ggshield.cmd.machine import machine_group
from ggshield.core.config.enterprise_config import (
    EnterpriseConfig,
    get_enterprise_config_filepath,
)
from ggshield.core.dirs import (
    get_system_data_dir,
    get_system_plugins_dir,
    make_tree_world_readable,
)
from ggshield.core.plugin.loader import PluginLoader
from ggshield.core.plugin.signature import SignatureVerificationMode
from ggshield.core.plugin.trust import PluginTrustStore, compute_file_sha256


posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX file modes only")


@pytest.fixture
def config_dirs(tmp_path, monkeypatch):
    user, system = tmp_path / "user-config", tmp_path / "system-config"
    monkeypatch.setenv("GG_CONFIG_DIR", str(user))
    monkeypatch.setenv("GG_SYSTEM_CONFIG_DIR", str(system))
    return user, system


def _write_config(config_dir: Path, body: str) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "enterprise_config.yaml").write_text(body)


def test_filepath_selects_system_or_user(config_dirs):
    user, system = config_dirs
    assert (
        get_enterprise_config_filepath(system=False) == user / "enterprise_config.yaml"
    )
    assert (
        get_enterprise_config_filepath(system=True) == system / "enterprise_config.yaml"
    )


def test_load_effective_merges_system_and_user(config_dirs, monkeypatch):
    user, system = config_dirs
    monkeypatch.setattr(ec_mod, "is_root", lambda: False)
    _write_config(system, "plugins:\n  machine_scan:\n    enabled: true\n")
    _write_config(user, "plugins:\n  other:\n    enabled: true\n")

    cfg = EnterpriseConfig.load_effective()

    assert cfg.is_plugin_enabled("machine_scan")  # machine-wide
    assert cfg.is_plugin_enabled("other")  # per-user


def test_user_entry_overrides_system(config_dirs, monkeypatch):
    user, system = config_dirs
    monkeypatch.setattr(ec_mod, "is_root", lambda: False)
    _write_config(system, "plugins:\n  machine_scan:\n    enabled: true\n")
    _write_config(user, "plugins:\n  machine_scan:\n    enabled: false\n")

    assert EnterpriseConfig.load_effective().is_plugin_enabled("machine_scan") is False


def test_load_effective_system_wins_for_root(config_dirs, monkeypatch):
    """For root the system file wins on conflict, so a stale per-user entry
    cannot shadow what 'plugin enable/disable' just wrote machine-wide."""
    user, system = config_dirs
    monkeypatch.setattr(ec_mod, "is_root", lambda: True)
    _write_config(system, "plugins:\n  machine_scan:\n    enabled: true\n")
    _write_config(user, "plugins:\n  machine_scan:\n    enabled: false\n")

    assert EnterpriseConfig.load_effective().is_plugin_enabled("machine_scan") is True


def test_load_effective_keeps_user_only_plugin_for_root(config_dirs, monkeypatch):
    """Root still merges the per-user layer as a fallback, so a pre-machine-wide
    root install whose enablement lives only per-user stays visible."""
    user, system = config_dirs
    monkeypatch.setattr(ec_mod, "is_root", lambda: True)
    _write_config(system, "plugins:\n  machine_scan:\n    enabled: true\n")
    _write_config(user, "plugins:\n  legacy_root:\n    enabled: true\n")

    cfg = EnterpriseConfig.load_effective()
    assert cfg.is_plugin_enabled("machine_scan")  # system
    assert cfg.is_plugin_enabled("legacy_root")  # per-user fallback


def test_effective_sources_order_and_flags(config_dirs, monkeypatch):
    user, system = config_dirs
    _write_config(system, "plugins:\n  machine_scan:\n    enabled: true\n")

    monkeypatch.setattr(ec_mod, "is_root", lambda: False)
    sources = EnterpriseConfig.effective_sources()
    assert [(s.scope, s.path, s.exists) for s in sources] == [
        ("system", system / "enterprise_config.yaml", True),
        ("user", user / "enterprise_config.yaml", False),
    ]
    assert "machine_scan" in sources[0].plugins
    assert sources[1].plugins == {}

    monkeypatch.setattr(ec_mod, "is_root", lambda: True)
    assert [s.scope for s in EnterpriseConfig.effective_sources()] == [
        "user",
        "system",
    ]


def test_effective_sources_keeps_parse_error_and_load_effective_raises(
    config_dirs, monkeypatch
):
    user, system = config_dirs
    monkeypatch.setattr(ec_mod, "is_root", lambda: False)
    _write_config(user, "plugins: [unclosed\n  : :")

    by_scope = {s.scope: s for s in EnterpriseConfig.effective_sources()}
    assert by_scope["user"].error is not None
    assert by_scope["user"].plugins == {}
    with pytest.raises(ValueError):
        EnterpriseConfig.load_effective()


@pytest.mark.parametrize("root", [False, True])
def test_load_effective_stops_at_system_config_read_error(
    config_dirs, monkeypatch, root
):
    user, system = config_dirs
    for module in (
        "ggshield.cmd.plugin.plugin_list",
        "ggshield.core.config.enterprise_config",
        "ggshield.core.dirs",
        "ggshield.core.plugin.downloader",
    ):
        monkeypatch.setattr(f"{module}.is_root", lambda: root)
    _write_config(system, "plugins: [unclosed\n  : :")
    _write_config(user, "plugins:\n  other: true\n")
    read_yaml = Mock(wraps=ec_mod.load_yaml_dict)
    monkeypatch.setattr(ec_mod, "load_yaml_dict", read_yaml)

    with pytest.raises(ValueError, match="is not a valid YAML file"):
        EnterpriseConfig.load_effective()

    read_yaml.assert_called_once_with(
        get_enterprise_config_filepath(system=True), strict_mapping=False
    )


def test_load_is_single_file_per_user_when_not_root(config_dirs, monkeypatch):
    user, system = config_dirs
    monkeypatch.setattr(ec_mod, "is_root", lambda: False)
    _write_config(system, "plugins:\n  sys_only:\n    enabled: true\n")
    _write_config(user, "plugins:\n  user_only:\n    enabled: true\n")

    cfg = EnterpriseConfig.load()

    assert cfg.is_plugin_enabled("user_only")
    assert "sys_only" not in cfg.plugins  # load() does not merge — load_effective does


def test_load_and_save_target_system_file_when_root(config_dirs, monkeypatch):
    user, system = config_dirs
    monkeypatch.setattr(ec_mod, "is_root", lambda: True)

    cfg = EnterpriseConfig.load()
    cfg.enable_plugin("machine_scan")
    cfg.save()

    system_file = system / "enterprise_config.yaml"
    assert system_file.exists()
    assert not (user / "enterprise_config.yaml").exists()
    # World-readable so every user can see machine-wide enablement.
    assert system_file.stat().st_mode & 0o044
    assert EnterpriseConfig.load().is_plugin_enabled("machine_scan")


def test_save_targets_user_file_when_not_root(config_dirs, monkeypatch):
    user, system = config_dirs
    monkeypatch.setattr(ec_mod, "is_root", lambda: False)

    cfg = EnterpriseConfig.load()
    cfg.enable_plugin("machine_scan")
    cfg.save()

    assert (user / "enterprise_config.yaml").exists()
    assert not (system / "enterprise_config.yaml").exists()


def _scanned_dirs(loader, monkeypatch) -> list[Path]:
    scanned: list[Path] = []
    monkeypatch.setattr(
        loader, "_scan_wheels_in", lambda d: scanned.append(d) or iter(())
    )
    list(loader._scan_local_wheels())
    return scanned


def test_loader_scans_both_dirs_user_wins_for_non_root(tmp_path, monkeypatch):
    """Non-root scans both; the per-user dir is yielded last so a user's own
    install wins (discover_plugins keys by name, last write wins)."""
    monkeypatch.setenv("GG_DATA_DIR", str(tmp_path / "user-data"))
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(tmp_path / "system-data"))
    monkeypatch.setattr("ggshield.core.dirs.is_root", lambda: False)
    loader = PluginLoader(EnterpriseConfig())

    scanned = _scanned_dirs(loader, monkeypatch)

    assert scanned == [
        tmp_path / "system-data" / "plugins",
        tmp_path / "user-data" / "plugins",
    ]
    assert loader.plugin_search_dirs() == scanned


def test_loader_scans_both_dirs_system_wins_for_root(tmp_path, monkeypatch):
    """Root scans both, with the system dir yielded last so a fresh machine-wide
    install wins over a stale /root wheel, while pre-existing per-user installs
    stay loadable."""
    monkeypatch.setenv("GG_DATA_DIR", str(tmp_path / "user-data"))
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(tmp_path / "system-data"))
    monkeypatch.setattr("ggshield.core.dirs.is_root", lambda: True)
    loader = PluginLoader(EnterpriseConfig())

    scanned = _scanned_dirs(loader, monkeypatch)

    assert scanned == [
        tmp_path / "user-data" / "plugins",
        tmp_path / "system-data" / "plugins",
    ]
    assert loader.plugin_search_dirs() == scanned


def test_plugin_search_dirs_deduplicated_when_dirs_are_equal(tmp_path, monkeypatch):
    shared = tmp_path / "shared"
    monkeypatch.setenv("GG_DATA_DIR", str(shared))
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(shared))
    monkeypatch.setattr("ggshield.core.dirs.is_root", lambda: False)

    assert PluginLoader(EnterpriseConfig()).plugin_search_dirs() == [shared / "plugins"]


def test_downloader_installs_to_system_dir_as_root(tmp_path, monkeypatch):
    monkeypatch.setenv("GG_DATA_DIR", str(tmp_path / "user-data"))
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(tmp_path / "system-data"))
    monkeypatch.setattr(dl_mod, "is_root", lambda: True)

    assert dl_mod.PluginDownloader().plugins_dir == tmp_path / "system-data" / "plugins"


def test_downloader_installs_to_user_dir_as_non_root(tmp_path, monkeypatch):
    monkeypatch.setenv("GG_DATA_DIR", str(tmp_path / "user-data"))
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(tmp_path / "system-data"))
    monkeypatch.setattr(dl_mod, "is_root", lambda: False)

    assert dl_mod.PluginDownloader().plugins_dir == tmp_path / "user-data" / "plugins"


def _write_system_install(system_data: Path, name: str, version: str) -> Path:
    """Create a minimal machine-wide install (manifest + dummy wheel)."""
    plugin_dir = system_data / "plugins" / name
    plugin_dir.mkdir(parents=True)
    wheel_filename = f"{name}-{version}.whl"
    (plugin_dir / wheel_filename).write_text("dummy")
    (plugin_dir / "manifest.json").write_text(
        json.dumps(
            {
                "plugin_name": name,
                "version": version,
                "wheel_filename": wheel_filename,
                "sha256": "deadbeef",
                "source": {"type": "platform"},
            }
        )
    )
    return plugin_dir


def test_downloader_reads_system_install_as_non_root(tmp_path, monkeypatch):
    """A non-root user must see a plugin root installed machine-wide; otherwise
    'plugin status' would report it as merely available."""
    monkeypatch.setenv("GG_DATA_DIR", str(tmp_path / "user-data"))
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(tmp_path / "system-data"))
    monkeypatch.setattr(dl_mod, "is_root", lambda: False)
    _write_system_install(tmp_path / "system-data", "machine_scan", "1.2.3")

    downloader = dl_mod.PluginDownloader()

    assert downloader.plugins_dir == tmp_path / "user-data" / "plugins"
    assert downloader.is_installed("machine_scan")
    assert downloader.get_installed_version("machine_scan") == "1.2.3"


def test_downloader_reads_legacy_user_install_as_root(tmp_path, monkeypatch):
    """Root must still see a plugin installed per-user before machine-wide
    existed (so status/update keep working until it is migrated)."""
    monkeypatch.setenv("GG_DATA_DIR", str(tmp_path / "user-data"))
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(tmp_path / "system-data"))
    monkeypatch.setattr(dl_mod, "is_root", lambda: True)
    _write_system_install(tmp_path / "user-data", "legacy_root", "0.9.0")

    downloader = dl_mod.PluginDownloader()

    assert downloader.plugins_dir == tmp_path / "system-data" / "plugins"
    assert downloader.get_installed_version("legacy_root") == "0.9.0"


def test_signature_label_uses_system_trust_store_for_non_root(tmp_path, monkeypatch):
    """status/list must report a machine-wide --allow-unsigned plugin as
    trusted, reading the same system trust store the loader does — not the
    empty per-user one."""
    monkeypatch.setenv("GG_DATA_DIR", str(tmp_path / "user-data"))
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(tmp_path / "system-data"))
    monkeypatch.setattr(dl_mod, "is_root", lambda: False)

    system_plugins = tmp_path / "system-data" / "plugins"
    plugin_dir = system_plugins / "machine_scan"
    plugin_dir.mkdir(parents=True)
    wheel = plugin_dir / "machine_scan-1.0.0.whl"
    wheel.write_text("dummy-wheel-bytes")
    sha = compute_file_sha256(wheel)
    (plugin_dir / "manifest.json").write_text(
        json.dumps(
            {
                "plugin_name": "machine_scan",
                "version": "1.0.0",
                "wheel_filename": "machine_scan-1.0.0.whl",
                "sha256": sha,
                "source": {"type": "platform"},
                "signature": {"status": "missing"},
            }
        )
    )
    # Trust recorded system-side, as a root --allow-unsigned install would.
    PluginTrustStore(plugins_dir=system_plugins).trust_plugin(
        "machine_scan", sha, "missing"
    )

    label = dl_mod.PluginDownloader().get_installed_signature_label("machine_scan")

    assert label == "unsigned (trusted)"


def test_loader_trusts_system_unsigned_plugin_for_non_root(tmp_path, monkeypatch):
    """A machine-wide unsigned plugin records its trust next to the system
    plugins; a non-root load must consult that store, not just the per-user
    one, or strict verification rejects an admin-installed wheel."""
    monkeypatch.setenv("GG_DATA_DIR", str(tmp_path / "user-data"))
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(tmp_path / "system-data"))

    system_plugins = tmp_path / "system-data" / "plugins"
    plugin_dir = system_plugins / "machine_scan"
    plugin_dir.mkdir(parents=True)
    wheel = plugin_dir / "machine_scan-1.0.0.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(
            "machine_scan-1.0.0.dist-info/entry_points.txt",
            "[ggshield.plugins]\nmachine = machine_scan:Plugin\n",
        )

    PluginTrustStore(plugins_dir=system_plugins).trust_plugin(
        "machine_scan", compute_file_sha256(wheel), "missing"
    )

    loader = PluginLoader(
        EnterpriseConfig(), signature_mode=SignatureVerificationMode.STRICT
    )

    # The per-user store knows nothing; only the system store does.
    assert loader.trust_store.get_record("machine_scan") is None
    assert loader._is_trusted_unsigned_plugin(wheel) is True


@posix_only
def test_make_tree_world_readable_widens_dirs_and_files(tmp_path):
    root = tmp_path / "tree"
    sub = root / "plugin"
    sub.mkdir(parents=True)
    wheel = sub / "plugin.whl"
    wheel.write_text("x")
    for directory in (root, sub):
        directory.chmod(0o700)
    wheel.chmod(0o600)

    make_tree_world_readable(root)

    assert root.stat().st_mode & 0o755 == 0o755
    assert sub.stat().st_mode & 0o755 == 0o755
    assert wheel.stat().st_mode & 0o644 == 0o644


@posix_only
def test_system_plugins_dir_traversable_under_restrictive_umask(tmp_path, monkeypatch):
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(tmp_path / "system-data"))
    old_umask = os.umask(0o077)
    try:
        plugins_dir = get_system_plugins_dir(create=True)
    finally:
        os.umask(old_umask)

    # Both the data parent and the plugins leaf must be world-traversable.
    assert get_system_data_dir().stat().st_mode & 0o055 == 0o055
    assert plugins_dir.stat().st_mode & 0o055 == 0o055


@posix_only
def test_system_plugins_dir_widens_created_ancestors(tmp_path, monkeypatch):
    """Intermediate dirs of a nested system path that mkdir creates must be
    world-traversable too, or non-root users cannot reach the install."""
    nested = tmp_path / "deep" / "nested" / "sysdata"
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(nested))
    old_umask = os.umask(0o077)
    try:
        plugins_dir = get_system_plugins_dir(create=True)
    finally:
        os.umask(old_umask)

    for created in (
        tmp_path / "deep",
        tmp_path / "deep" / "nested",
        nested,
        plugins_dir,
    ):
        assert created.stat().st_mode & 0o055 == 0o055, created


def test_resolve_plugin_dir_user_entry_point_wins_over_system_direct(
    tmp_path, monkeypatch
):
    """A non-root user's own install (under its distribution-name dir, matched
    by entry point) must win over a machine-wide install of the same name, so
    the downloader resolves the same layer the loader loads."""
    monkeypatch.setenv("GG_DATA_DIR", str(tmp_path / "user-data"))
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(tmp_path / "system-data"))
    monkeypatch.setattr(dl_mod, "is_root", lambda: False)

    # Per-user: dir named after the distribution, entry point "foo".
    user_dir = tmp_path / "user-data" / "plugins" / "foo-dist"
    user_dir.mkdir(parents=True)
    wheel = user_dir / "foo_dist-2.0.0.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(
            "foo_dist-2.0.0.dist-info/entry_points.txt",
            "[ggshield.plugins]\nfoo = foo_dist:Plugin\n",
        )
    (user_dir / "manifest.json").write_text(
        json.dumps(
            {
                "plugin_name": "foo-dist",
                "version": "2.0.0",
                "wheel_filename": "foo_dist-2.0.0.whl",
                "sha256": "x",
                "source": {"type": "platform"},
            }
        )
    )

    # System: machine-wide install under the direct name "foo".
    _write_system_install(tmp_path / "system-data", "foo", "1.0.0")

    downloader = dl_mod.PluginDownloader()

    assert downloader.get_installed_version("foo") == "2.0.0"


@posix_only
def test_root_save_makes_system_config_dir_traversable(config_dirs, monkeypatch):
    user, system = config_dirs
    monkeypatch.setattr(ec_mod, "is_root", lambda: True)

    old_umask = os.umask(0o077)
    try:
        cfg = EnterpriseConfig.load()
        cfg.enable_plugin("machine_scan")
        cfg.save()
    finally:
        os.umask(old_umask)

    config_file = system / "enterprise_config.yaml"
    # File world-readable AND its parent dir world-traversable, so a non-root
    # user can actually reach and read the machine-wide enablement.
    assert config_file.stat().st_mode & 0o044 == 0o044
    assert system.stat().st_mode & 0o055 == 0o055


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        # Basic-auth userinfo is dropped.
        (
            "https://user:secret@example.com/p-1.0.0.whl",
            "https://example.com/p-1.0.0.whl",
        ),
        # Presigned-token query string is dropped.
        (
            "https://bucket.s3.amazonaws.com/p.whl?X-Amz-Signature=deadbeef",
            "https://bucket.s3.amazonaws.com/p.whl",
        ),
        # A credential-free URL is preserved as-is.
        (
            "https://example.com/urlplugin-1.0.0.whl",
            "https://example.com/urlplugin-1.0.0.whl",
        ),
        # Port is kept, fragment dropped.
        ("https://host:8443/p.whl#frag", "https://host:8443/p.whl"),
    ],
)
def test_redact_url_credentials(url, expected):
    assert dl_mod._redact_url_credentials(url) == expected


def test_redact_url_credentials_passthrough_for_empty():
    assert dl_mod._redact_url_credentials(None) is None
    assert dl_mod._redact_url_credentials("") == ""


# --- Machine-wide dirs spread over every XDG entry --------------------------

linux_only = pytest.mark.skipif(
    sys.platform != "linux", reason="exercises platformdirs' XDG handling"
)

PLUGIN_SOURCE = textwrap.dedent(
    """
    import click

    from ggshield.core.plugin.base import GGShieldPlugin, PluginMetadata

    class Plugin(GGShieldPlugin):
        @property
        def metadata(self):
            return PluginMetadata(
                name="{name}",
                version="1.0.0",
                display_name="{name}",
                description="xdg test plugin",
                min_ggshield_version="1.0.0",
            )

        def register(self, registry):
            @click.group()
            def machine():
                pass

            @machine.command()
            def scan():
                click.echo("Scan from {name}")

            registry.register_command(machine)
    """
)


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Fixed system dirs and XDG entries under tmp_path, plus user dirs.

    Limit discovery to tmp_path because the real filter rejects /tmp."""
    layout = SimpleNamespace(
        fixed_data=tmp_path / "fixed-data",
        fixed_conf=tmp_path / "fixed-conf",
        user_data=tmp_path / "user-data",
        user_conf=tmp_path / "user-config",
        tmp=tmp_path,
    )
    monkeypatch.delenv("GG_SYSTEM_DATA_DIR", raising=False)
    monkeypatch.delenv("GG_SYSTEM_CONFIG_DIR", raising=False)
    monkeypatch.setenv("GG_DATA_DIR", str(layout.user_data))
    monkeypatch.setenv("GG_CONFIG_DIR", str(layout.user_conf))
    monkeypatch.setattr(dirs_mod, "_LINUX_SYSTEM_DATA_DIR", layout.fixed_data)
    monkeypatch.setattr(dirs_mod, "_LINUX_SYSTEM_CONFIG_DIR", layout.fixed_conf)
    monkeypatch.setattr(
        dirs_mod, "_is_safe_system_dir", lambda p: p.is_relative_to(tmp_path)
    )
    monkeypatch.delenv("XDG_DATA_DIRS", raising=False)
    monkeypatch.delenv("XDG_CONFIG_DIRS", raising=False)

    def set_xdg(data: Sequence[Path] = (), config: Sequence[Path] = ()) -> None:
        monkeypatch.setenv("XDG_DATA_DIRS", os.pathsep.join(map(str, data)))
        monkeypatch.setenv("XDG_CONFIG_DIRS", os.pathsep.join(map(str, config)))

    def entry(name: str) -> Path:
        """An XDG entry holding a ggshield dir, e.g. ``/usr/share/gnome``."""
        path = tmp_path / name
        (path / "ggshield").mkdir(parents=True, exist_ok=True)
        return path

    def run_as(root: bool) -> None:
        for module in (dirs_mod, ec_mod, dl_mod):
            monkeypatch.setattr(module, "is_root", lambda: root)

    layout.set_xdg, layout.entry, layout.run_as = set_xdg, entry, run_as
    layout.monkeypatch = monkeypatch
    return layout


def _make_plugin(
    app_dir: Path, ep_name: str, version: str = "1.0.0", dist: str = "xdg-dist"
) -> Path:
    """Install an unsigned plugin (wheel, manifest, trust record) in the
    ``plugins`` dir of ``app_dir`` (a ``.../ggshield`` data dir)."""
    plugins_dir = app_dir / "plugins"
    plugin_dir = plugins_dir / dist
    plugin_dir.mkdir(parents=True)
    wheel = plugin_dir / f"{ep_name}-{version}.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(f"{ep_name}.py", PLUGIN_SOURCE.format(name=ep_name))
        zf.writestr(
            f"{ep_name}-{version}.dist-info/entry_points.txt",
            f"[ggshield.plugins]\n{ep_name} = {ep_name}:Plugin\n",
        )
    sha = compute_file_sha256(wheel)
    (plugin_dir / "manifest.json").write_text(
        json.dumps(
            {
                "plugin_name": dist,
                "version": version,
                "wheel_filename": wheel.name,
                "sha256": sha,
                "source": {"type": "platform"},
                "signature": {"status": "missing"},
            }
        )
    )
    PluginTrustStore(plugins_dir=plugins_dir).trust_plugin(dist, sha, "missing")
    return plugin_dir


def _enable(conf_app_dir: Path, ep_name: str) -> None:
    _write_config(conf_app_dir, f"plugins:\n  {ep_name}:\n    enabled: true\n")


def _new_ep_name() -> str:
    return f"xdgplug_{uuid.uuid4().hex[:8]}"


def _loader() -> PluginLoader:
    return PluginLoader(
        EnterpriseConfig.load_effective(),
        signature_mode=SignatureVerificationMode.STRICT,
    )


def _loaded_names(loader: PluginLoader) -> list[str]:
    return list(loader.load_enabled_plugins().get_all_plugins())


@linux_only
@pytest.mark.parametrize("root", [True, False])
def test_fixed_dir_plugin_is_loaded_from_any_xdg_session(
    layout: SimpleNamespace, root: bool, cli_fs_runner
) -> None:
    """Installed from a plain session, loaded from a GNOME-like one."""
    ep = _new_ep_name()
    layout.run_as(True)
    install_dir = dl_mod.PluginDownloader().plugins_dir
    assert install_dir == layout.fixed_data / "plugins"
    _make_plugin(install_dir.parent, ep)
    config = EnterpriseConfig.load()
    config.enable_plugin(ep)
    config.save()

    layout.set_xdg(
        data=[layout.entry("gnome"), layout.entry("share")],
        config=[layout.entry("xdg-ubuntu"), layout.entry("xdg")],
    )

    assert dl_mod.PluginDownloader().plugins_dir == install_dir
    assert EnterpriseConfig.load().is_plugin_enabled(ep)
    layout.run_as(root)
    # The lazy group adds commands in place, so isolate the merge per test.
    layout.monkeypatch.setattr(machine_group, "commands", machine_group.commands.copy())
    result = cli_fs_runner.invoke(cli, ["machine", "scan"])
    assert result.exit_code == 0, result.output
    assert f"Scan from {ep}" in result.output
    downloader = dl_mod.PluginDownloader()
    assert downloader.get_installed_version(ep) == "1.0.0"
    assert downloader.get_installed_signature_label(ep) == "unsigned (trusted)"


@linux_only
@pytest.mark.parametrize("root", [True, False])
def test_secondary_xdg_plugin_uses_its_own_trust_record(
    layout: SimpleNamespace, root: bool
) -> None:
    ep = _new_ep_name()
    layout.run_as(root)
    gnome = layout.entry("gnome")
    conf = layout.entry("xdg-ubuntu")
    layout.set_xdg(data=[gnome], config=[conf])
    _make_plugin(gnome / "ggshield", ep)
    _enable(conf / "ggshield", ep)

    assert ep in _loaded_names(_loader())
    downloader = dl_mod.PluginDownloader()
    assert downloader.get_installed_version(ep) == "1.0.0"
    assert downloader.get_installed_signature_label(ep) == "unsigned (trusted)"


@linux_only
@pytest.mark.parametrize("trust_file", ["missing", "group-writable", "symlink"])
def test_secondary_xdg_plugin_requires_safe_trust_record(
    layout: SimpleNamespace, trust_file: str
) -> None:
    ep = _new_ep_name()
    layout.run_as(False)
    gnome = layout.entry("gnome")
    layout.set_xdg(data=[gnome])
    plugin_dir = _make_plugin(gnome / "ggshield", ep)
    store_path = plugin_dir.parent.parent / "plugin_trust.json"
    if trust_file == "missing":
        store_path.unlink()
    elif trust_file == "group-writable":
        store_path.chmod(0o664)
    else:
        target = store_path.rename(layout.tmp / "other-trust.json")
        store_path.symlink_to(target)
    _enable(layout.fixed_conf, ep)

    assert ep not in _loaded_names(_loader())
    assert dl_mod.PluginDownloader().get_installed_signature_label(ep) == "missing"


@linux_only
@pytest.mark.parametrize(
    "unsafe",
    ["group-writable wheel", "foreign-owned wheel", "manifest", "bundle", "dir"],
)
def test_unsafe_secondary_plugin_is_ignored(
    layout: SimpleNamespace, unsafe: str
) -> None:
    ep = _new_ep_name()
    gnome = layout.entry("gnome")
    layout.set_xdg(data=[gnome])
    plugin_dir = _make_plugin(gnome / "ggshield", ep)
    wheel = next(plugin_dir.glob("*.whl"))
    if unsafe == "group-writable wheel":
        wheel.chmod(0o664)
    elif unsafe == "foreign-owned wheel":
        real_lstat = Path.lstat

        def lstat(path: Path):
            info = real_lstat(path)
            if path == wheel:
                return SimpleNamespace(st_mode=info.st_mode, st_uid=os.geteuid() + 1)
            return info

        layout.monkeypatch.setattr(Path, "lstat", lstat)
    elif unsafe == "manifest":
        manifest = plugin_dir / "manifest.json"
        target = manifest.rename(layout.tmp / "other-manifest.json")
        manifest.symlink_to(target)
    elif unsafe == "bundle":
        wheel.with_name(wheel.name + ".sigstore.json").symlink_to(layout.tmp / "absent")
    else:
        target = plugin_dir.rename(layout.tmp / "other-plugin")
        plugin_dir.symlink_to(target, target_is_directory=True)

    assert ep not in [plugin.name for plugin in _loader().discover_plugins()]
    downloader = dl_mod.PluginDownloader()
    assert downloader.get_manifest(ep) is None
    assert downloader.get_manifest(plugin_dir.name) is None


@linux_only
@pytest.mark.parametrize("root", [True, False])
def test_fixed_dir_wins_over_secondary_in_loader_and_downloader(
    layout: SimpleNamespace, root: bool
) -> None:
    ep = _new_ep_name()
    layout.run_as(root)
    gnome = layout.entry("gnome")
    layout.set_xdg(data=[gnome])
    _make_plugin(gnome / "ggshield", ep, version="1.0.0")
    _make_plugin(layout.fixed_data, ep, version="2.0.0")

    versions = {p.name: p.version for p in _loader().discover_plugins()}
    assert versions[ep] == "2.0.0"
    assert dl_mod.PluginDownloader().get_installed_version(ep) == "2.0.0"


@linux_only
def test_secondary_is_used_when_fixed_dir_has_no_such_plugin(
    layout: SimpleNamespace,
) -> None:
    ep = _new_ep_name()
    layout.run_as(True)
    gnome = layout.entry("gnome")
    layout.set_xdg(data=[gnome])
    _make_plugin(gnome / "ggshield", ep, version="1.0.0")
    layout.fixed_data.mkdir()

    versions = {p.name: p.version for p in _loader().discover_plugins()}
    assert versions[ep] == "1.0.0"
    assert dl_mod.PluginDownloader().get_installed_version(ep) == "1.0.0"


@linux_only
@pytest.mark.parametrize(
    "problem",
    [
        "list",
        "invalid UTF-8",
        "missing version",
        "unsafe filename",
        "unreadable wheel",
        "truncated wheel",
        "unlistable dir",
    ],
)
def test_invalid_secondary_install_falls_back_in_loader_and_downloader(
    layout: SimpleNamespace, problem: str
) -> None:
    ep = _new_ep_name()
    layout.run_as(True)
    first = layout.entry("first")
    second = layout.entry("second")
    layout.set_xdg(data=[first, second])
    plugin_dir = _make_plugin(first / "ggshield", ep)
    _make_plugin(second / "ggshield", ep, version="2.0.0")
    manifest_path = plugin_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())

    if problem == "list":
        manifest_path.write_text("[]")
    elif problem == "invalid UTF-8":
        manifest_path.write_bytes(b"\xff")
    elif problem == "missing version":
        del manifest["version"]
        manifest_path.write_text(json.dumps(manifest))
    elif problem == "unsafe filename":
        manifest["wheel_filename"] = "./" + manifest["wheel_filename"]
        manifest_path.write_text(json.dumps(manifest))
    elif problem == "truncated wheel":
        wheel = plugin_dir / manifest["wheel_filename"]
        wheel.write_bytes(wheel.read_bytes()[:20])
    elif problem == "unlistable dir":
        # Mode 0711 for a non-root reader: traversable but not listable.
        plugins_dir = plugin_dir.parent
        real_access, real_iterdir = os.access, Path.iterdir
        layout.monkeypatch.setattr(
            os,
            "access",
            lambda path, mode: path != plugins_dir and real_access(path, mode),
        )

        def iterdir(self: Path) -> Iterator[Path]:
            if self == plugins_dir:
                raise PermissionError(13, "denied")
            return real_iterdir(self)

        layout.monkeypatch.setattr(Path, "iterdir", iterdir)
    else:
        wheel = plugin_dir / manifest["wheel_filename"]
        real_access = os.access
        layout.monkeypatch.setattr(
            os, "access", lambda path, mode: path != wheel and real_access(path, mode)
        )

    versions = {p.name: p.version for p in _loader().discover_plugins()}
    assert versions[ep] == "2.0.0"
    downloader = dl_mod.PluginDownloader()
    assert downloader.get_installed_version(ep) == "2.0.0"
    assert downloader.get_installed_version(plugin_dir.name) == "2.0.0"


@linux_only
def test_root_prefers_system_dirs_over_legacy_root_install(
    layout: SimpleNamespace,
) -> None:
    ep = _new_ep_name()
    layout.run_as(True)
    gnome = layout.entry("gnome")
    layout.set_xdg(data=[gnome])
    _make_plugin(layout.user_data, ep, version="0.9.0")
    _make_plugin(gnome / "ggshield", ep, version="1.0.0")

    versions = {p.name: p.version for p in _loader().discover_plugins()}
    assert versions[ep] == "1.0.0"
    assert dl_mod.PluginDownloader().get_installed_version(ep) == "1.0.0"


@linux_only
def test_non_root_user_install_wins_over_every_system_dir(
    layout: SimpleNamespace,
) -> None:
    ep = _new_ep_name()
    layout.run_as(False)
    gnome = layout.entry("gnome")
    layout.set_xdg(data=[gnome])
    _make_plugin(layout.user_data, ep, version="3.0.0")
    _make_plugin(layout.fixed_data, ep, version="2.0.0")
    _make_plugin(gnome / "ggshield", ep, version="1.0.0")

    versions = {p.name: p.version for p in _loader().discover_plugins()}
    assert versions[ep] == "3.0.0"
    assert dl_mod.PluginDownloader().get_installed_version(ep) == "3.0.0"


@linux_only
@pytest.mark.parametrize("root", [True, False])
def test_unreadable_system_dir_does_not_hide_the_next_one(
    layout: SimpleNamespace, root: bool
) -> None:
    ep = _new_ep_name()
    layout.run_as(root)
    broken, good = layout.entry("broken"), layout.entry("good")
    layout.set_xdg(data=[broken, good])
    (broken / "ggshield" / "plugins").mkdir()
    _make_plugin(good / "ggshield", ep)
    real_iterdir = Path.iterdir

    def iterdir(self: Path) -> Iterator[Path]:
        if self == broken / "ggshield" / "plugins":
            raise PermissionError(13, "denied")
        return real_iterdir(self)

    layout.monkeypatch.setattr(Path, "iterdir", iterdir)

    assert ep in [p.name for p in _loader().discover_plugins()]
    assert dl_mod.PluginDownloader().get_installed_version(ep) == "1.0.0"


@linux_only
def test_uninstall_revokes_trust_record_in_the_plugins_own_dir(
    layout: SimpleNamespace,
) -> None:
    ep = _new_ep_name()
    layout.run_as(True)
    gnome = layout.entry("gnome")
    layout.set_xdg(data=[gnome])
    plugins_dir = gnome / "ggshield" / "plugins"
    _make_plugin(gnome / "ggshield", ep)
    store = PluginTrustStore(plugins_dir=plugins_dir)
    assert store.get_record("xdg-dist") is not None

    assert dl_mod.PluginDownloader().uninstall(ep) is True

    assert not (plugins_dir / "xdg-dist").exists()
    assert store.get_record("xdg-dist") is None


@linux_only
def test_enterprise_config_is_merged_across_xdg_config_dirs(
    layout: SimpleNamespace,
) -> None:
    layout.run_as(False)
    first, second = layout.entry("conf-a"), layout.entry("conf-b")
    layout.set_xdg(config=[first, second])
    _write_config(
        layout.fixed_conf,
        "plugins:\n  both:\n    enabled: false\n  fixed_only:\n    enabled: true\n",
    )
    _write_config(
        first / "ggshield",
        "plugins:\n  both:\n    enabled: true\n  first_only:\n    enabled: true\n",
    )
    _write_config(
        second / "ggshield",
        "plugins:\n  first_only:\n    enabled: false\n  second_only:\n    enabled: true\n",
    )

    cfg = EnterpriseConfig.load_effective()

    assert cfg.is_plugin_enabled("fixed_only")
    assert cfg.is_plugin_enabled("both") is False  # fixed beats the XDG entries
    assert cfg.is_plugin_enabled("first_only")  # earlier entry beats later one
    assert cfg.is_plugin_enabled("second_only")


@linux_only
def test_enterprise_config_ignores_unsafe_xdg_config_dir(
    layout: SimpleNamespace,
) -> None:
    layout.run_as(False)
    bad = layout.entry("bad")
    layout.set_xdg(config=[bad])
    _write_config(bad / "ggshield", "plugins:\n  planted:\n    enabled: true\n")
    layout.monkeypatch.setattr(
        dirs_mod, "_is_safe_system_dir", lambda p: "bad" not in p.parts
    )

    assert not EnterpriseConfig.load_effective().is_plugin_enabled("planted")


@linux_only
@pytest.mark.parametrize(
    "problem",
    [
        "unreadable",
        "invalid YAML",
        "group-writable",
        "plugins:",
        "plugins: []",
        "[]",
        "null",
        'plugins:\n  secondary:\n    enabled: "true"\n',
    ],
)
def test_bad_secondary_config_leaves_fixed_and_user_config_available(
    layout: SimpleNamespace, problem: str, caplog: pytest.LogCaptureFixture
) -> None:
    secondary = layout.entry("other-conf")
    layout.set_xdg(config=[secondary])
    _enable(layout.fixed_conf, "fixed")
    _enable(layout.user_conf, "user")
    _enable(secondary / "ggshield", "secondary")
    path = secondary / "ggshield" / "enterprise_config.yaml"

    if problem == "unreadable":
        real_open = Path.open

        def open_config(self: Path, *args, **kwargs):
            if self == path:
                raise PermissionError(13, "denied")
            return real_open(self, *args, **kwargs)

        layout.monkeypatch.setattr(Path, "open", open_config)
    elif problem == "invalid YAML":
        path.write_text("plugins: [")
    elif problem == "group-writable":
        path.chmod(0o664)
    else:
        path.write_text(problem)

    with caplog.at_level("DEBUG", logger=ec_mod.__name__):
        cfg = EnterpriseConfig.load_effective()
    assert cfg.is_plugin_enabled("fixed")
    assert cfg.is_plugin_enabled("user")
    assert not cfg.is_plugin_enabled("secondary")
    if problem != "group-writable":
        assert "Cannot load secondary enterprise config" in caplog.text


@linux_only
@pytest.mark.parametrize("root", [True, False])
def test_enterprise_config_user_and_system_precedence_with_xdg_dirs(
    layout: SimpleNamespace, root: bool
) -> None:
    layout.run_as(root)
    other = layout.entry("conf-a")
    layout.set_xdg(config=[other])
    _write_config(other / "ggshield", "plugins:\n  p:\n    enabled: true\n")
    _write_config(layout.user_conf, "plugins:\n  p:\n    enabled: false\n")

    # Non-root: own file wins; root: the system layer wins.
    assert EnterpriseConfig.load_effective().is_plugin_enabled("p") is root


@linux_only
def test_enterprise_config_save_and_load_stay_on_the_fixed_file(
    layout: SimpleNamespace,
) -> None:
    layout.run_as(True)
    other = layout.entry("conf-a")
    layout.set_xdg(config=[other])
    _write_config(other / "ggshield", "plugins:\n  elsewhere:\n    enabled: true\n")

    cfg = EnterpriseConfig.load()
    assert "elsewhere" not in cfg.plugins
    cfg.enable_plugin("mine")
    cfg.save()

    assert (layout.fixed_conf / "enterprise_config.yaml").exists()
    assert get_enterprise_config_filepath(system=True) == (
        layout.fixed_conf / "enterprise_config.yaml"
    )


def test_malformed_manifest_metadata_does_not_break_listing() -> None:
    assert dl_mod.get_signature_label({"signature": "missing"}) is None


def test_malformed_trust_store_is_treated_as_empty(tmp_path: Path) -> None:
    path = tmp_path / "plugin_trust.json"
    for content in (b"[]", b"\xff"):
        path.write_bytes(content)
        assert PluginTrustStore(path).get_record("any") is None


@linux_only
@pytest.mark.parametrize("root", [True, False])
def test_plugin_list_verbose_shows_every_xdg_entry(
    layout: SimpleNamespace, root: bool, cli_fs_runner
) -> None:
    """`plugin list -v` lists each XDG entry searched, and the ones skipped."""
    from ggshield.cmd.plugin import plugin_list as plugin_list_mod

    ep = _new_ep_name()
    layout.run_as(root)
    layout.monkeypatch.setattr(plugin_list_mod, "is_root", lambda: root)
    gnome, bad = layout.entry("gnome"), layout.entry("bad")
    conf, bad_conf = layout.entry("xdg-ubuntu"), layout.entry("bad-conf")
    missing = layout.tmp / "missing"
    layout.set_xdg(data=[gnome, bad, missing], config=[conf, bad_conf, bad])
    layout.monkeypatch.setattr(
        dirs_mod, "_is_safe_system_dir", lambda p: p.exists() and "bad" not in p.parts
    )
    _make_plugin(gnome / "ggshield", ep)
    _enable(conf / "ggshield", ep)
    (bad_conf / "ggshield" / "enterprise_config.yaml").write_text("plugins: [")

    result = cli_fs_runner.invoke(cli, ["plugin", "list", "-v"])

    assert result.exit_code == 0, result.output
    out = result.output
    assert f"  {gnome / 'ggshield' / 'plugins'}\n    xdg-dist: {ep} v1.0.0" in out
    assert f"  {layout.fixed_data / 'plugins'} (not found)" in out
    assert "  Skipped XDG_DATA_DIRS entries:" in out
    assert f"    {bad / 'ggshield' / 'plugins'} (ignored: not owned by root" in out
    assert f"    {missing / 'ggshield' / 'plugins'} (not found)" in out
    conf_file = conf / "ggshield" / "enterprise_config.yaml"
    assert f"  {conf_file} (system, XDG_CONFIG_DIRS)\n    {ep}: enabled" in out
    invalid_file = bad_conf / "ggshield" / "enterprise_config.yaml"
    assert f"  {invalid_file} (system, XDG_CONFIG_DIRS)\n" in out
    assert "    ignored by ggshield: invalid: " in out
    assert "  Skipped XDG_CONFIG_DIRS entries:" in out
    unsafe_file = bad / "ggshield" / "enterprise_config.yaml"
    assert f"    {unsafe_file} (ignored: not owned by root" in out
    assert f"  {ep}: enabled, from {conf_file}" in out
