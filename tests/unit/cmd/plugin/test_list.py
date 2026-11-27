"""
Tests for the enterprise list command.
"""

import json
import os
import zipfile
from pathlib import Path
from unittest import mock

import pytest

import ggshield.cmd.plugin.plugin_list as plugin_list_module
from ggshield.__main__ import cli
from ggshield.core.config.enterprise_config import (
    EnterpriseConfig,
    get_enterprise_config_filepath,
)
from ggshield.core.dirs import get_plugins_dir, get_system_plugins_dir
from ggshield.core.errors import ExitCode
from ggshield.core.plugin import hooks
from ggshield.core.plugin.client import PluginSource, PluginSourceType
from ggshield.core.plugin.loader import DiscoveredPlugin, PluginLoader
from ggshield.core.plugin.registry import PluginRegistry


def _run_list(cli_fs_runner, plugins, source_for_name=None, signature_label=None):
    """Invoke `ggshield plugin list` with mocked loader + downloader.

    ``source_for_name`` is a mapping of ``plugin name -> PluginSource | None``
    returned by the patched ``PluginDownloader.get_plugin_source``.
    """
    source_for_name = source_for_name or {}
    with (
        mock.patch.object(plugin_list_module, "PluginLoader") as mock_loader_class,
        mock.patch.object(
            plugin_list_module, "PluginDownloader"
        ) as mock_downloader_class,
    ):
        mock_loader = mock.MagicMock()
        mock_loader.discover_plugins.return_value = plugins
        mock_loader_class.return_value = mock_loader

        mock_downloader = mock.MagicMock()
        mock_downloader.get_plugin_source.side_effect = (
            lambda name: source_for_name.get(name)
        )
        mock_downloader.get_installed_signature_label.return_value = signature_label
        mock_downloader_class.return_value = mock_downloader

        return cli_fs_runner.invoke(cli, ["plugin", "list"])


class TestPluginList:
    """Tests for 'ggshield plugin list' command."""

    def test_list_no_plugins(self, cli_fs_runner):
        """
        GIVEN no plugins installed
        WHEN running 'ggshield plugin list'
        THEN it shows a message about no plugins
        """
        result = _run_list(cli_fs_runner, plugins=[])

        assert result.exit_code == ExitCode.SUCCESS
        assert "No plugins installed" in result.output
        assert "ggshield plugin status" in result.output

    def test_list_flags_enabled_plugin_that_failed_to_load(self, cli_fs_runner):
        """
        GIVEN an enabled plugin recorded as failed-to-load in the registry
        WHEN running 'ggshield plugin list'
        THEN its line says "FAILED TO LOAD" with the reason, not just "enabled"
        """
        plugins = [
            DiscoveredPlugin(
                name="machine_scan",
                entry_point=mock.MagicMock(),
                wheel_path=None,
                is_installed=True,
                is_enabled=True,
                version="0.59.0",
            ),
        ]
        registry = PluginRegistry()
        registry.record_load_failure(
            "machine_scan", "manylinux wheel cannot load on a musl host"
        )

        with mock.patch.object(
            plugin_list_module, "load_plugin_registry", return_value=registry
        ):
            result = _run_list(cli_fs_runner, plugins)

        assert result.exit_code == ExitCode.SUCCESS
        assert "machine_scan" in result.output
        assert "FAILED TO LOAD" in result.output
        assert "musl host" in result.output

    def test_list_pip_plugin_without_wheel(self, cli_fs_runner):
        """
        GIVEN a plugin discovered only via a Python entry point (pip-installed,
              no on-disk wheel)
        WHEN running 'ggshield plugin list'
        THEN the source column is "pip" — ``get_plugin_source`` is not called
             because there's no wheel/manifest to consult.
        """
        plugins = [
            DiscoveredPlugin(
                name="testplugin",
                entry_point=mock.MagicMock(),
                wheel_path=None,
                is_installed=True,
                is_enabled=True,
                version="1.0.0",
            ),
        ]

        result = _run_list(cli_fs_runner, plugins)

        assert result.exit_code == ExitCode.SUCCESS
        assert "testplugin" in result.output
        assert "enabled" in result.output
        assert "pip" in result.output

    @pytest.mark.parametrize(
        "source_type, expected_label",
        [
            (PluginSourceType.PLATFORM, "platform"),
            (PluginSourceType.LOCAL_FILE, "local file"),
            (PluginSourceType.URL, "url"),
            (PluginSourceType.GITHUB_RELEASE, "github release"),
            (PluginSourceType.GITHUB_ARTIFACT, "github artifact"),
        ],
    )
    def test_list_surfaces_manifest_source(
        self, cli_fs_runner, source_type, expected_label
    ):
        """
        GIVEN a wheel-installed plugin whose manifest records a ``source.type``
        WHEN running 'ggshield plugin list'
        THEN the source column mirrors the manifest value (with underscores
             replaced by spaces for readability) — tells the user WHERE the
             plugin came from, which the previous "local" label hid.
        """
        plugins = [
            DiscoveredPlugin(
                name="machine_scan",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=True,
                version="0.32.0",
            ),
        ]

        result = _run_list(
            cli_fs_runner,
            plugins,
            source_for_name={"machine_scan": PluginSource(type=source_type)},
            signature_label="signed",
        )

        assert result.exit_code == ExitCode.SUCCESS
        assert "machine_scan" in result.output
        assert expected_label in result.output
        # The legacy label must not leak through for any recognised source type.
        assert ", local," not in result.output
        assert "signature: signed" in result.output

    def test_list_legacy_wheel_without_manifest_falls_back_to_on_disk(
        self, cli_fs_runner
    ):
        """
        GIVEN a wheel on disk with no readable manifest
              (hand-dropped file — rare edge case)
        WHEN running 'ggshield plugin list'
        THEN the source column is "on-disk" rather than silently empty.
        """
        plugins = [
            DiscoveredPlugin(
                name="mystery_wheel",
                entry_point=None,
                wheel_path=Path("/path/to/wheel"),
                is_installed=True,
                is_enabled=False,
                version="0.1.0",
            ),
        ]

        result = _run_list(
            cli_fs_runner,
            plugins,
            # No entry for "mystery_wheel" → get_plugin_source returns None.
        )

        assert result.exit_code == ExitCode.SUCCESS
        assert "mystery_wheel" in result.output
        assert "on-disk" in result.output

    def test_list_plugin_versions(self, cli_fs_runner):
        """
        GIVEN plugins with version info
        WHEN running 'ggshield plugin list'
        THEN it shows the version numbers
        """
        plugins = [
            DiscoveredPlugin(
                name="versioned",
                entry_point=mock.MagicMock(),
                wheel_path=None,
                is_installed=True,
                is_enabled=True,
                version="3.2.1",
            ),
        ]

        result = _run_list(cli_fs_runner, plugins)

        assert result.exit_code == ExitCode.SUCCESS
        assert "v3.2.1" in result.output


@pytest.fixture
def real_list(monkeypatch, cli_fs_runner):
    """Run `plugin list` against real files under the GG_*_DIR dirs."""
    monkeypatch.setattr(PluginLoader, "_get_entry_points", lambda self: iter(()))

    def run(*args, root=False, use_real_registry=False):
        for module in (
            "ggshield.cmd.plugin.plugin_list",
            "ggshield.core.config.enterprise_config",
            "ggshield.core.dirs",
            "ggshield.core.plugin.downloader",
        ):
            monkeypatch.setattr(f"{module}.is_root", lambda: root)
        if not use_real_registry:
            monkeypatch.setattr(
                plugin_list_module, "load_plugin_registry", PluginRegistry
            )
        return cli_fs_runner.invoke(cli, ["plugin", "list", *args])

    return run


def _write_config(system: bool, body: str) -> Path:
    path = get_enterprise_config_filepath(system=system)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    return path


def _install_wheel(
    plugins_dir: Path, folder: str, version: str, entry_point: str = "machine_scan"
) -> Path:
    plugin_dir = plugins_dir / folder
    plugin_dir.mkdir(parents=True)
    distribution = folder.replace("-", "_")
    wheel = plugin_dir / f"{distribution}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as zf:
        zf.writestr(
            f"{distribution}-{version}.dist-info/entry_points.txt",
            f"[ggshield.plugins]\n{entry_point} = {distribution}:Plugin\n",
        )
    (plugin_dir / "manifest.json").write_text(
        json.dumps(
            {
                "plugin_name": folder,
                "version": version,
                "wheel_filename": wheel.name,
                "source": {"type": "platform"},
            }
        )
    )
    return wheel


class TestPluginListVerbose:
    """Tests for 'ggshield plugin list -v'."""

    def test_non_verbose_output_has_no_diagnostics(self, real_list):
        result = real_list()

        assert result.exit_code == ExitCode.SUCCESS
        assert "No plugins installed" in result.output
        assert "Plugin directories" not in result.output
        assert "Enterprise config files" not in result.output

    @pytest.mark.parametrize("root", [False, True])
    def test_no_plugins_shows_dirs_and_config_files_without_creating_dirs(
        self, real_list, root
    ):
        """
        GIVEN empty GG_* dirs
        WHEN running 'plugin list -v'
        THEN every searched dir and config file is shown as not found, and the
             command creates none of the plugin dirs
        """
        result = real_list("-v", root=root)

        assert result.exit_code == ExitCode.SUCCESS
        assert "No plugins installed" in result.output
        with mock.patch("ggshield.core.dirs.is_root", lambda: root):
            search_dirs = PluginLoader(mock.MagicMock()).plugin_search_dirs()
        printed = [
            line.strip()
            for line in result.output.split("Enterprise config files")[0].splitlines()
            if "(not found)" in line
        ]
        assert printed == [f"{d} (not found)" for d in search_dirs]
        for scope in ("system", "user"):
            path = get_enterprise_config_filepath(system=scope == "system")
            assert f"{path} ({scope}) (not found)" in result.output
        assert "(none: plugins are disabled unless enabled here)" in result.output
        assert not get_plugins_dir().exists()
        assert not get_system_plugins_dir().exists()

    def test_existing_empty_plugin_directory(self, real_list):
        system_dir = get_system_plugins_dir()
        system_dir.mkdir(parents=True)

        result = real_list("-v")

        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert f"  {system_dir}\n    (empty)\n" in result.output
        assert f"  {get_plugins_dir()} (not found)\n" in result.output

    def test_unlistable_plugin_directory(self, real_list, monkeypatch):
        user_dir = get_plugins_dir()
        user_dir.mkdir(parents=True)
        system_dir = get_system_plugins_dir()
        _install_wheel(system_dir, "satori-python", "0.59.0")
        original_iterdir = Path.iterdir

        def iterdir(path):
            if path == user_dir:
                raise PermissionError("permission denied")
            yield from original_iterdir(path)

        monkeypatch.setattr(Path, "iterdir", iterdir)

        result = real_list("-v")

        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert "  machine_scan: v0.59.0, disabled" in result.output
        assert (
            f"  {system_dir}\n    satori-python: machine_scan v0.59.0\n"
            in result.output
        )
        assert f"  {user_dir}\n    cannot list: permission denied\n" in result.output

    @pytest.mark.parametrize("root", [False, True])
    def test_plugin_directory_is_a_regular_file(self, real_list, root):
        bad_dir = get_system_plugins_dir() if root else get_plugins_dir()
        good_dir = get_plugins_dir() if root else get_system_plugins_dir()
        bad_dir.parent.mkdir(parents=True)
        bad_dir.touch()
        _install_wheel(good_dir, "satori-python", "0.59.0")

        result = real_list("-v", root=root)

        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert "  machine_scan: v0.59.0, disabled" in result.output
        assert (
            f"  {good_dir}\n    satori-python: machine_scan v0.59.0\n" in result.output
        )
        assert f"  {bad_dir}\n    cannot list: " in result.output

    def test_loose_wheel_is_reported_as_skipped(self, real_list):
        system_dir = get_system_plugins_dir()
        system_dir.mkdir(parents=True)
        wheel = system_dir / "example-1.0.0-py3-none-any.whl"
        wheel.touch()
        (system_dir / "other.txt").touch()

        result = real_list("-v")

        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert "No plugins installed." in result.output
        assert (
            f"  {system_dir}\n    {wheel.name}: wheel file outside a plugin folder "
            "(not loaded; install with 'ggshield plugin install')\n" in result.output
        )
        assert "other.txt" not in result.output

    @pytest.mark.parametrize("root", [False, True])
    def test_precedence_context_and_environment_overrides(
        self, real_list, monkeypatch, root
    ):
        monkeypatch.setattr(plugin_list_module.getpass, "getuser", lambda: "test-user")

        result = real_list("-v", root=root)

        assert result.exit_code == ExitCode.SUCCESS, result.output
        context = (
            "Running as root: system dirs and files take precedence."
            if root
            else "Running as test-user: per-user dirs and files take precedence."
        )
        diagnostic_lines = result.output.splitlines()
        start = diagnostic_lines.index(context)
        names = (
            "GG_CONFIG_DIR",
            "GG_DATA_DIR",
            "GG_SYSTEM_CONFIG_DIR",
            "GG_SYSTEM_DATA_DIR",
        )
        assert diagnostic_lines[start + 1 : start + 5] == [
            f"Overridden by environment: {name}={os.environ[name]}" for name in names
        ]

    def test_precedence_context_without_username(self, real_list, monkeypatch):
        def getuser():
            raise OSError("no username available")

        monkeypatch.setattr(plugin_list_module.getpass, "getuser", getuser)

        result = real_list("-v")

        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert (
            "Running as a non-root user: per-user dirs and files take precedence."
            in result.output
        )

    @pytest.mark.parametrize(
        "root, enabled, winner_scope",
        [(False, False, "user"), (True, True, "system")],
    )
    def test_conflicting_configs(self, real_list, root, enabled, winner_scope):
        """
        GIVEN a system file enabling machine_scan and a user file disabling it
        WHEN running 'plugin list -v'
        THEN the effective row comes from the file that wins for this user,
             and every file's own values are shown
        """
        system_file = _write_config(
            True,
            "plugins:\n  machine_scan:\n    enabled: true\n"
            "    version: 0.58.0\n    auto_update: false\n",
        )
        user_file = _write_config(
            False, "plugins:\n  machine_scan:\n    enabled: false\n"
        )
        winner = system_file if winner_scope == "system" else user_file

        result = real_list("-v", root=root)

        assert result.exit_code == ExitCode.SUCCESS, result.output
        output = result.output
        state = "enabled" if enabled else "disabled"
        assert f"  machine_scan: {state}, from {winner}" in output
        # The row the winner overrides is marked, with its own values.
        overridden_row = (
            "machine_scan: disabled   (overridden)"
            if root
            else "machine_scan: enabled, version 0.58.0, auto_update false   (overridden)"
        )
        assert overridden_row in output
        assert output.count("(overridden)") == 1
        # Recorded fields only matter (and are noted) when the winning row has them.
        assert ("recorded version 0.58.0, auto_update false" in output) == root
        assert ("are not enforced" in output) == root
        # Only the enabled row has no installed plugin to match.
        assert ("no installed plugin with this name was found" in output) == enabled

    def test_config_file_order_follows_precedence(self, real_list):
        system_file = _write_config(True, "plugins:\n  a:\n    enabled: true\n")
        user_file = _write_config(False, "plugins:\n  a:\n    enabled: false\n")

        out = real_list("-v", root=False).output
        assert out.index(str(system_file)) < out.index(str(user_file))
        out = real_list("-v", root=True).output
        assert out.index(str(user_file)) < out.index(str(system_file))

    @pytest.mark.parametrize("root", [False, True])
    def test_removing_one_file_shows_not_found_and_other_source(self, real_list, root):
        system_file = _write_config(
            True, "plugins:\n  machine_scan:\n    enabled: true\n"
        )
        user_file = _write_config(
            False, "plugins:\n  machine_scan:\n    enabled: false\n"
        )

        user_file.unlink()
        result = real_list("-v", root=root)
        assert result.exit_code == ExitCode.SUCCESS, result.output
        out = result.output
        assert f"{user_file} (user) (not found)" in out
        assert f"machine_scan: enabled, from {system_file}" in out

        _write_config(False, "plugins:\n  machine_scan:\n    enabled: false\n")
        system_file.unlink()
        result = real_list("-v", root=root)
        assert result.exit_code == ExitCode.SUCCESS, result.output
        out = result.output
        assert f"{system_file} (system) (not found)" in out
        assert f"machine_scan: disabled, from {user_file}" in out

    def test_invalid_config_blocks_runtime_plugin_loading(self, real_list):
        _install_wheel(get_system_plugins_dir(), "satori-python", "0.59.0")
        user_file = _write_config(False, "plugins:\n  machine_scan: true\n")
        system_file = _write_config(True, "plugins: [unclosed\n  : :")

        result = real_list("-v", use_real_registry=True)

        assert result.exit_code == ExitCode.SUCCESS, result.output
        registry = hooks.get_plugin_registry()
        assert registry is not None
        assert not registry.get_all_plugins()
        load_error = hooks.get_plugin_load_error()
        assert load_error is not None
        assert f"{system_file} is not a valid YAML file" in load_error
        installed = (
            "  machine_scan: v0.59.0, enabled in config, but not loaded: "
            f"could not read {system_file}, platform"
        )
        assert installed in result.output.splitlines()
        diagnostics = result.output.split(f"  {system_file} (system)\n", 1)[1]
        diagnostic_lines = diagnostics.splitlines()
        error_lines = load_error.splitlines()
        assert diagnostic_lines[: len(error_lines)] == [
            f"    error: {error_lines[0]}",
            *(f"    {line}" for line in error_lines[1:]),
        ]
        effective = result.output.split("Effective plugin config:\n", 1)[1]
        assert effective.startswith(
            f"  error: {system_file} could not be read; ggshield loads no plugins "
            f"until it is fixed (rows below ignore that file)\n"
            f"  machine_scan: enabled, from {user_file}\n"
        )

    @pytest.mark.parametrize("root", [False, True])
    def test_unsearchable_config_path_takes_priority_over_user_error(
        self, real_list, root
    ):
        _write_config(False, "plugins: [unclosed\n  : :")
        system_file = get_enterprise_config_filepath(system=True)
        original_exists = Path.exists

        def exists(path, *args, **kwargs):
            if path == system_file:
                raise PermissionError("config directory is unsearchable")
            return original_exists(path, *args, **kwargs)

        with mock.patch.object(Path, "exists", exists):
            result = real_list("-v", root=root)
            with pytest.raises(
                PermissionError, match="config directory is unsearchable"
            ):
                EnterpriseConfig.load_effective()

        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert (
            f"  {system_file} (system)\n    error: config directory is unsearchable\n"
            in result.output
        )

    def test_inaccessible_config_file_is_reported_and_ignored(self, real_list):
        """Python 3.14's Path.exists() reports a permission error as missing:
        say the file cannot be checked instead of "(not found)"."""
        system_file = get_enterprise_config_filepath(system=True)
        original_exists, original_stat = Path.exists, Path.stat

        def exists(path, *args, **kwargs):
            if path == system_file:
                return False
            return original_exists(path, *args, **kwargs)

        def stat(path, *args, **kwargs):
            if path == system_file:
                raise PermissionError("permission denied")
            return original_stat(path, *args, **kwargs)

        with (
            mock.patch.object(Path, "exists", exists),
            mock.patch.object(Path, "stat", stat),
        ):
            result = real_list("-v")
            assert EnterpriseConfig.load_effective().plugins == {}

        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert (
            f"  {system_file} (system)\n"
            "    cannot access, ignored by ggshield: permission denied\n"
            in result.output
        )
        assert "could not be read" not in result.output

    def test_mixed_yaml_key_types_are_sorted(self, real_list):
        system_file = _write_config(True, "plugins:\n  on: true\n  a-plugin: false\n")

        result = real_list("-v")

        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert (
            f"  {system_file} (system)\n    True: enabled\n    a-plugin: disabled\n"
            in result.output
        )
        assert f"  True: enabled, from {system_file}" in result.output

    def test_wheel_plugin_details_and_shadowing(self, real_list):
        system_wheel = _install_wheel(
            get_system_plugins_dir(), "satori-python", "0.59.0"
        )
        user_wheel = _install_wheel(get_plugins_dir(), "satori-python", "0.58.0")
        (get_plugins_dir() / "foo").mkdir()
        _write_config(
            True,
            "plugins:\n  satori-python:\n    enabled: true\n    version: 0.50.0\n",
        )

        result = real_list("-v")  # non-root: the user install wins

        assert result.exit_code == ExitCode.SUCCESS, result.output
        out = result.output
        assert "  machine_scan: v0.58.0, disabled" not in out
        assert "  machine_scan: v0.58.0, enabled, platform" in out
        assert "    package: satori-python" in out
        assert f"    manifest: {user_wheel.parent / 'manifest.json'}" in out
        assert f"    wheel: {user_wheel}" in out
        assert "    config key: satori-python (legacy alias)" in out
        assert (
            f"  {get_plugins_dir()}\n    foo: no manifest.json\n    satori-python: machine_scan v0.58.0\n"
            in out
        )
        assert (
            "    satori-python: machine_scan v0.59.0 "
            f"(shadowed by {user_wheel.parent})"
        ) in out
        assert "recorded version 0.50.0 (installed 0.58.0)" in out
        assert str(system_wheel.parent.parent) in out
        # The legacy-alias row matches the installed plugin: no warning.
        assert "no installed plugin with this name" not in out

    def test_legacy_alias_is_ignored_when_canonical_key_exists(self, real_list):
        _install_wheel(get_system_plugins_dir(), "satori-python", "0.59.0")
        system_file = _write_config(True, "plugins:\n  satori-python: true\n")
        user_file = _write_config(False, "plugins:\n  machine_scan: false\n")

        result = real_list("-v")

        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert "  machine_scan: v0.59.0, disabled" in result.output
        assert f"  machine_scan: disabled, from {user_file}\n" in result.output
        assert (
            f"  satori-python: enabled, from {system_file} (ignored: machine_scan decides)\n"
            in result.output
        )

    @pytest.mark.parametrize("root", [False, True])
    def test_config_key_match_takes_precedence_over_package_name(self, real_list, root):
        _install_wheel(get_system_plugins_dir(), "foo", "1.0.0", entry_point="bar")
        _install_wheel(get_plugins_dir(), "other", "2.0.0", entry_point="foo")
        config = _write_config(
            True, "plugins:\n  bar: true\n  foo:\n    version: 0.20.0\n"
        )

        result = real_list("-v", root=root)

        assert result.exit_code == ExitCode.SUCCESS, result.output
        assert (
            f"  foo: enabled, from {config}\n"
            "    recorded version 0.20.0 (installed 2.0.0), auto_update true\n"
            in result.output
        )

    @pytest.mark.parametrize(
        "contents, error",
        [
            (b'["not an object"]', "expected a JSON object"),
            (b"\xff", "'utf-8' codec can't decode byte"),
            (None, ""),  # A directory in place of the manifest raises OSError.
        ],
        ids=["non-object", "non-utf8", "read-error"],
    )
    def test_invalid_manifest_does_not_hide_valid_install(
        self, real_list, contents, error
    ):
        _install_wheel(get_system_plugins_dir(), "satori-python", "0.59.0")
        broken = get_plugins_dir() / "broken"
        broken.mkdir(parents=True)
        manifest = broken / "manifest.json"
        if contents is None:
            manifest.mkdir()
        else:
            manifest.write_bytes(contents)

        result = real_list("-v")

        assert result.exit_code == ExitCode.SUCCESS, result.output
        # The downloader skips the broken neighbour like discovery does, so
        # the valid install keeps its source label.
        assert "  machine_scan: v0.59.0, disabled, platform\n" in result.output
        assert (
            f"  {get_system_plugins_dir()}\n    satori-python: machine_scan v0.59.0\n"
            in result.output
        )
        assert (
            f"  {get_plugins_dir()}\n    broken: invalid manifest: {error}"
            in result.output
        )

    def test_wheel_plugin_without_config_row(self, real_list):
        _install_wheel(get_system_plugins_dir(), "satori-python", "0.59.0")

        out = real_list("-v").output

        assert "  machine_scan: v0.59.0, disabled" in out
        assert "    config key: none (not listed in any config file)" in out
