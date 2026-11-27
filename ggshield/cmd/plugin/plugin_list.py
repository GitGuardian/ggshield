"""
Plugin list command.
"""

import getpass
import os
from pathlib import Path
from textwrap import indent
from typing import Any, Dict, List, Optional

import click

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.core import ui
from ggshield.core.config.enterprise_config import (
    EnterpriseConfig,
    EnterpriseConfigSource,
    PluginConfig,
)
from ggshield.core.dirs import (
    IgnoredDirs,
    get_system_config_dirs,
    get_system_plugins_dirs,
    is_root,
)
from ggshield.core.plugin.downloader import PluginDownloader
from ggshield.core.plugin.hooks import load_plugin_registry
from ggshield.core.plugin.loader import DiscoveredPlugin, PluginLoader


NOT_ENFORCED_NOTE = (
    "note: 'version' and 'auto_update' are recorded at install time and are "
    "not enforced (no pinning, no automatic update)."
)


@click.command("list")
@add_common_options()
@click.pass_context
def list_cmd(ctx: click.Context, **kwargs: Any) -> None:
    """
    List installed plugins.

    Shows all plugins that are currently installed on your system,
    along with their version and enabled/disabled status.

    Use -v to also show where plugins and configuration are read from.

    Use 'ggshield plugin status' to see available plugins
    that can be installed.
    """
    verbose = ui.is_verbose()
    sources: List[EnterpriseConfigSource] = []
    if verbose:
        sources = EnterpriseConfig.effective_sources()
        enterprise_config = EnterpriseConfig.from_sources(sources)
    else:
        enterprise_config = EnterpriseConfig.load_effective()
    loader = PluginLoader(enterprise_config)
    invalid_config = next((s.path for s in sources if s.error is not None), None)

    # Snapshot the directories before the downloader can create them.
    found_dirs: Dict[Path, bool] = {}
    if verbose:
        for directory in loader.plugin_search_dirs():
            try:
                found_dirs[directory] = directory.is_dir()
            except OSError:
                found_dirs[directory] = False  # Discovery records the error.

    discovered = loader.discover_plugins()

    if not discovered:
        ui.display_info("No plugins installed.")
        ui.display_info("")
        ui.display_info("To see available plugins:")
        ui.display_info("  ggshield plugin status")
        ui.display_info("")
        ui.display_info("To install a plugin:")
        ui.display_info("  ggshield plugin install <plugin_name>")
        if verbose:
            _display_diagnostics(
                loader, discovered, enterprise_config, sources, found_dirs
            )
        return

    # Discovery tolerates broken entries; the downloader may not, so degrade its
    # labels instead of hiding the listing.
    has_scan_errors = bool(loader.skipped_entries)
    try:
        downloader = PluginDownloader()
    except OSError:
        if not has_scan_errors:
            raise
        downloader = None

    ui.display_heading("Installed Plugins")

    registry = load_plugin_registry()
    load_failures = registry.get_load_failures() if registry else {}

    for plugin in discovered:
        status_parts = []

        if plugin.version:
            status_parts.append(f"v{plugin.version}")

        if not plugin.is_enabled:
            status_parts.append("disabled")
        elif invalid_config is not None:
            status_parts.append(
                f"enabled in config, but not loaded: could not read {invalid_config}"
            )
        elif plugin.name in load_failures:
            status_parts.append(
                f"enabled, FAILED TO LOAD: {load_failures[plugin.name]}"
            )
        else:
            status_parts.append("enabled")

        source = None
        sig_label = None
        if downloader is not None:
            try:
                if plugin.wheel_path:
                    source = downloader.get_plugin_source(plugin.name)
                sig_label = downloader.get_installed_signature_label(plugin.name)
            except Exception:
                if not has_scan_errors:
                    raise
        if source is not None:
            status_parts.append(source.type.value.replace("_", " "))
        elif plugin.entry_point:
            status_parts.append("pip")
        elif plugin.wheel_path:
            status_parts.append("on-disk")

        if sig_label:
            status_parts.append(f"signature: {sig_label}")

        status = ", ".join(status_parts)
        ui.display_info(f"  {plugin.name}: {status}")
        if verbose:
            _display_plugin_details(plugin)

    if verbose:
        _display_diagnostics(loader, discovered, enterprise_config, sources, found_dirs)


def _display_plugin_details(plugin: DiscoveredPlugin) -> None:
    if plugin.package_name:
        ui.display_info(f"    package: {plugin.package_name}")
    if plugin.wheel_path:
        if plugin.manifest_path:
            ui.display_info(f"    manifest: {plugin.manifest_path}")
        ui.display_info(f"    wheel: {plugin.wheel_path}")
    elif plugin.entry_point:
        ui.display_info(f"    entry point: {plugin.entry_point.value}")

    if plugin.config_key is None:
        key = "none (not listed in any config file)"
    elif plugin.config_key != plugin.name:
        key = f"{plugin.config_key} (legacy alias)"
    else:
        key = plugin.config_key
    ui.display_info(f"    config key: {key}")


def _display_diagnostics(
    loader: PluginLoader,
    discovered: List[DiscoveredPlugin],
    enterprise_config: EnterpriseConfig,
    sources: List[EnterpriseConfigSource],
    found_dirs: Dict[Path, bool],
) -> None:
    """Show where plugins and enterprise config were looked for, and what won."""
    ui.display_info("")
    if is_root():
        ui.display_info("Running as root: system dirs and files take precedence.")
    else:
        try:
            user = getpass.getuser()
        except (ImportError, KeyError, OSError):
            user = "a non-root user"
        ui.display_info(f"Running as {user}: per-user dirs and files take precedence.")
    for name in (
        "GG_CONFIG_DIR",
        "GG_DATA_DIR",
        "GG_SYSTEM_CONFIG_DIR",
        "GG_SYSTEM_DATA_DIR",
    ):
        if name in os.environ:
            ui.display_info(f"Overridden by environment: {name}={os.environ[name]}")

    _display_plugin_dirs(loader, discovered, found_dirs)
    ignored_plugin_dirs: IgnoredDirs = []
    get_system_plugins_dirs(ignored_plugin_dirs)
    _display_ignored_dirs("XDG_DATA_DIRS", ignored_plugin_dirs)
    _display_config_files(sources)
    ignored_config_dirs: IgnoredDirs = []
    get_system_config_dirs(ignored_config_dirs)
    _display_ignored_dirs(
        "XDG_CONFIG_DIRS",
        [(path / "enterprise_config.yaml", why) for path, why in ignored_config_dirs],
    )
    _display_effective_config(discovered, enterprise_config, sources)


def _display_ignored_dirs(variable: str, ignored: IgnoredDirs) -> None:
    """Show the XDG entries left out of the lists above, and why."""
    if not ignored:
        return
    ui.display_info(f"  Skipped {variable} entries:")
    for path, reason in ignored:
        ui.display_info(f"    {path} ({reason})")


def _wheel_version(wheel_path: Path) -> str:
    """Version from a wheel filename (``name-version-tags.whl``)."""
    parts = wheel_path.name.split("-")
    return f" v{parts[1]}" if len(parts) > 1 else ""


def _display_plugin_dirs(
    loader: PluginLoader,
    discovered: List[DiscoveredPlugin],
    found_dirs: Dict[Path, bool],
) -> None:
    ui.display_info("")
    ui.display_info("Plugin directories (searched in this order, later wins):")
    scan_errors = {entry: reason for entry, reason in loader.skipped_entries}
    for plugins_dir, found in found_dirs.items():
        if plugins_dir in scan_errors:
            ui.display_info(f"  {plugins_dir}")
            ui.display_info(f"    {scan_errors[plugins_dir]}")
            continue
        if not found:
            ui.display_info(f"  {plugins_dir} (not found)")
            continue
        ui.display_info(f"  {plugins_dir}")

        lines = []
        for plugin in discovered:
            if plugin.wheel_path and plugin.wheel_path.parent.parent == plugins_dir:
                version = f" v{plugin.version}" if plugin.version else ""
                lines.append((plugin.wheel_path.parent.name, f"{plugin.name}{version}"))
            for shadowed in plugin.shadowed:
                if shadowed.parent.parent == plugins_dir and plugin.wheel_path:
                    lines.append(
                        (
                            shadowed.parent.name,
                            f"{plugin.name}{_wheel_version(shadowed)} "
                            f"(shadowed by {plugin.wheel_path.parent})",
                        )
                    )
        for entry, reason in loader.skipped_entries:
            if entry.parent == plugins_dir:
                lines.append((entry.name, reason))

        for folder, text in sorted(lines):
            ui.display_info(f"    {folder}: {text}")
        if not lines:
            ui.display_info("    (empty)")


def _recorded_fields(
    config: PluginConfig, installed_version: Optional[str] = None
) -> List[str]:
    fields = []
    if config.version is not None:
        version = f"version {config.version}"
        if installed_version and installed_version != config.version:
            version += f" (installed {installed_version})"
        fields.append(version)
    if fields or not config.auto_update:
        fields.append(f"auto_update {str(config.auto_update).lower()}")
    return fields


def _display_config_files(sources: List[EnterpriseConfigSource]) -> None:
    ui.display_info("")
    ui.display_info("Enterprise config files (read in this order, later wins):")
    for index, source in enumerate(sources):
        header = f"  {source.path} ({source.scope})"
        if source.error is not None:
            ui.display_info(header)
            ui.display_info(indent(f"error: {source.error}", "    ", lambda _: True))
            continue
        if source.inaccessible is not None:
            ui.display_info(header)
            ui.display_info(
                f"    cannot access, ignored by ggshield: {source.inaccessible}"
            )
            continue
        if source.ignored is not None:
            ui.display_info(header)
            ui.display_info(f"    ignored by ggshield: {source.ignored}")
            continue
        if not source.exists:
            ui.display_info(f"{header} (not found)")
            continue
        ui.display_info(header)
        for name in sorted(source.plugins, key=str):
            config = source.plugins[name]
            row = ", ".join(
                ["enabled" if config.enabled else "disabled", *_recorded_fields(config)]
            )
            overridden = any(name in later.plugins for later in sources[index + 1 :])
            suffix = "   (overridden)" if overridden else ""
            ui.display_info(f"    {name}: {row}{suffix}")
        if not source.plugins:
            ui.display_info("    (no plugins)")


def _find_plugin(
    discovered: List[DiscoveredPlugin], key: str
) -> Optional[DiscoveredPlugin]:
    for plugin in discovered:
        if key == (plugin.config_key or plugin.name):
            return plugin
    return next((plugin for plugin in discovered if key == plugin.package_name), None)


def _display_effective_config(
    discovered: List[DiscoveredPlugin],
    effective: EnterpriseConfig,
    sources: List[EnterpriseConfigSource],
) -> None:
    ui.display_info("")
    ui.display_info("Effective plugin config:")
    for source in sources:
        if source.error is not None:
            ui.display_info(
                f"  error: {source.path} could not be read; ggshield loads no plugins "
                "until it is fixed (rows below ignore that file)"
            )
    if not effective.plugins:
        ui.display_info("  (none: plugins are disabled unless enabled here)")
        return

    has_recorded_fields = False
    for name in sorted(effective.plugins, key=str):
        config = effective.plugins[name]
        winner = next(s for s in reversed(sources) if name in s.plugins)
        line = f"  {name}: {'enabled' if config.enabled else 'disabled'}, from {winner.path}"
        plugin = _find_plugin(discovered, name)
        if plugin is None and config.enabled:
            line += (
                " - no installed plugin with this name was found in the "
                "directories above"
            )
        elif plugin is not None and name == plugin.package_name:
            deciding_key = plugin.config_key or plugin.name
            if name != deciding_key:
                line += f" (ignored: {deciding_key} decides)"
        ui.display_info(line)

        fields = _recorded_fields(config, plugin.version if plugin else None)
        if fields:
            has_recorded_fields = True
            ui.display_info(f"    recorded {', '.join(fields)}")

    if has_recorded_fields:
        ui.display_info(f"  {NOT_ENFORCED_NOTE}")
