"""Machine-wide (transparent cross-user) plugin support.

Privilege decides where install/enable land (root → system, user → per-user);
reads merge both layers. Driven here via GG_*_DIR overrides + a monkeypatched
is_root so it runs without actually being root.
"""

from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

import pytest

import ggshield.core.config.enterprise_config as ec_mod
import ggshield.core.plugin.downloader as dl_mod
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
    monkeypatch.setattr("ggshield.core.plugin.loader.is_root", lambda: False)
    loader = PluginLoader(EnterpriseConfig())

    scanned = _scanned_dirs(loader, monkeypatch)

    assert scanned == [
        tmp_path / "system-data" / "plugins",
        tmp_path / "user-data" / "plugins",
    ]


def test_loader_scans_both_dirs_system_wins_for_root(tmp_path, monkeypatch):
    """Root scans both, with the system dir yielded last so a fresh machine-wide
    install wins over a stale /root wheel, while pre-existing per-user installs
    stay loadable."""
    monkeypatch.setenv("GG_DATA_DIR", str(tmp_path / "user-data"))
    monkeypatch.setenv("GG_SYSTEM_DATA_DIR", str(tmp_path / "system-data"))
    monkeypatch.setattr("ggshield.core.plugin.loader.is_root", lambda: True)
    loader = PluginLoader(EnterpriseConfig())

    scanned = _scanned_dirs(loader, monkeypatch)

    assert scanned == [
        tmp_path / "user-data" / "plugins",
        tmp_path / "system-data" / "plugins",
    ]


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
