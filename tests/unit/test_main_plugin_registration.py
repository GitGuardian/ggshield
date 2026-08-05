"""Tests for lazy plugin command registration (PluginAwareLazyGroup)."""

import sys
import types
from unittest import mock

import click
import pytest

from ggshield.cmd.utils.lazy_group import (
    PluginAwareLazyGroup,
    add_or_merge_plugin_command,
)


def _registry_with_commands(*commands, load_failures=None):
    registry = mock.MagicMock()
    registry.get_commands.return_value = list(commands)
    registry.get_load_failures.return_value = load_failures or {}
    return registry


def _patch_registry(monkeypatch, registry) -> None:
    monkeypatch.setattr(
        "ggshield.core.plugin.hooks.load_plugin_registry", lambda: registry
    )


def test_plugin_commands_merge_on_miss(monkeypatch) -> None:
    """A plugin command is registered when an unknown command name is resolved."""
    root = PluginAwareLazyGroup("cli", commands={"auth": click.Command("auth")})
    plugin_conflicting_cmd = click.Command("auth")
    plugin_new_cmd = click.Command("plugin-extra")
    _patch_registry(
        monkeypatch, _registry_with_commands(plugin_conflicting_cmd, plugin_new_cmd)
    )

    cmd = root.get_command(click.Context(root), "plugin-extra")

    assert cmd is plugin_new_cmd
    # Built-in auth must not be overridden by the conflicting plugin command
    assert root.commands["auth"] is not plugin_conflicting_cmd


def test_plugins_not_loaded_when_command_resolves(monkeypatch) -> None:
    """The whole point: resolving a known command must not load plugins."""
    root = PluginAwareLazyGroup("cli", commands={"auth": click.Command("auth")})
    monkeypatch.setattr(
        "ggshield.core.plugin.hooks.load_plugin_registry",
        lambda: pytest.fail("plugins must not be loaded to resolve a built-in command"),
    )

    assert root.get_command(click.Context(root), "auth") is not None


def test_add_or_merge_adds_new_top_level_command() -> None:
    """A plugin command with a fresh name is added as-is."""
    root = click.Group("cli", commands={"auth": click.Command("auth")})
    plugin_cmd = click.Command("brand-new")
    warnings: list[str] = []

    add_or_merge_plugin_command(root, plugin_cmd, warnings)

    assert root.commands["brand-new"] is plugin_cmd
    assert warnings == []


def test_add_or_merge_merges_plugin_group_into_builtin_group() -> None:
    """A plugin group colliding with a built-in group merges its subcommands in."""
    builtin_machine = click.Group("machine", commands={"setup": click.Command("setup")})
    root = click.Group("cli", commands={"machine": builtin_machine})
    plugin_machine = click.Group(
        "machine",
        commands={
            "scan": click.Command("scan"),
            "inventory": click.Command("inventory"),
            "setup": click.Command("setup"),  # conflicts with built-in
        },
    )
    warnings: list[str] = []

    add_or_merge_plugin_command(root, plugin_machine, warnings)

    # Plugin subcommands are merged into the SAME built-in group object.
    assert root.commands["machine"] is builtin_machine
    assert "scan" in builtin_machine.commands
    assert "inventory" in builtin_machine.commands
    # The built-in `setup` wins; the plugin's conflicting one is skipped.
    assert builtin_machine.commands["setup"].name == "setup"
    assert any("machine setup" in msg for msg in warnings)


def test_add_or_merge_loads_lazy_builtin_before_merging(monkeypatch) -> None:
    """A plugin command must not shadow a built-in that is still lazy."""
    # A fake lazy target module, so we don't mutate the real machine_group
    # singleton (test pollution).
    mod = types.ModuleType("fake_machine_mod")
    mod.machine_group = click.Group(  # type: ignore[attr-defined]
        "machine", commands={"setup": click.Command("setup")}
    )
    monkeypatch.setitem(sys.modules, "fake_machine_mod", mod)

    root = PluginAwareLazyGroup(
        "cli", lazy_commands={"machine": "fake_machine_mod:machine_group"}
    )
    plugin_machine = click.Group("machine", commands={"scan": click.Command("scan")})
    warnings: list[str] = []

    add_or_merge_plugin_command(root, plugin_machine, warnings)

    # The built-in machine group was force-loaded, plugin subcommands merged in.
    assert root.commands["machine"] is not plugin_machine
    assert "setup" in root.commands["machine"].commands
    assert "scan" in root.commands["machine"].commands


def test_add_or_merge_skips_non_group_conflict() -> None:
    """A plain command colliding with a built-in command is skipped, not merged."""
    root = click.Group("cli", commands={"auth": click.Command("auth")})
    plugin_cmd = click.Command("auth")
    warnings: list[str] = []

    add_or_merge_plugin_command(root, plugin_cmd, warnings)

    assert root.commands["auth"] is not plugin_cmd
    assert any("conflicts with an existing command" in msg for msg in warnings)


def test_plugin_scope_merges_subcommands_into_group(monkeypatch) -> None:
    """plugin_scope='machine' merges the plugin's machine subcommands in."""
    group = PluginAwareLazyGroup(
        "machine",
        plugin_scope="machine",
        lazy_commands={"setup": "fake_setup_mod:setup_cmd"},
    )
    plugin_machine = click.Group(
        "machine",
        commands={"scan": click.Command("scan"), "setup": click.Command("setup")},
    )
    _patch_registry(monkeypatch, _registry_with_commands(plugin_machine))

    cmd = group.get_command(click.Context(group), "scan")

    assert cmd is plugin_machine.commands["scan"]
    # The still-lazy built-in `setup` wins over the plugin's conflicting one.
    assert "setup" not in group.commands


def test_merging_twice_does_not_warn(monkeypatch) -> None:
    """GIVEN a plugin group whose name matches a built-in group
    WHEN both the root group and the built-in group itself merge it
    THEN the second merge is silent

    Both merge into the same object, so warning on the second pass would claim a
    plugin subcommand was dropped when it is in fact registered.
    """
    machine = PluginAwareLazyGroup("machine", plugin_scope="machine")
    mod = types.ModuleType("fake_machine_mod2")
    mod.machine = machine  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "fake_machine_mod2", mod)
    root = PluginAwareLazyGroup(
        "cli", lazy_commands={"machine": "fake_machine_mod2:machine"}
    )
    plugin_machine = click.Group("machine", commands={"scan": click.Command("scan")})
    _patch_registry(monkeypatch, _registry_with_commands(plugin_machine))

    warnings: list[str] = []
    monkeypatch.setattr("ggshield.core.ui.display_warning", warnings.append)

    root.list_commands(click.Context(root))  # root merges into `machine`
    machine.list_commands(click.Context(machine))  # `machine` merges again

    assert "scan" in machine.commands
    assert warnings == []


def test_load_failures_warn_on_command_miss(monkeypatch) -> None:
    """A failed plugin load warns when an unknown command is resolved."""
    from ggshield.core import ui
    from ggshield.core.plugin.registry import PluginRegistry

    registry = PluginRegistry()
    registry.record_load_failure("machine_scan", "error relocating libsatori.so")
    _patch_registry(monkeypatch, registry)

    warnings: list[str] = []
    monkeypatch.setattr(ui, "display_warning", warnings.append)

    group = PluginAwareLazyGroup("cli")
    assert group.get_command(click.Context(group), "missing") is None

    assert len(warnings) == 1
    assert "machine_scan" in warnings[0]
    assert "failed to load" in warnings[0].lower()


def test_load_failures_silent_during_shell_completion(monkeypatch) -> None:
    """Warnings must not leak into shell completion output."""
    from ggshield.core import ui
    from ggshield.core.plugin.registry import PluginRegistry

    registry = PluginRegistry()
    registry.record_load_failure("machine_scan", "error relocating libsatori.so")
    _patch_registry(monkeypatch, registry)
    monkeypatch.setenv("_GGSHIELD_COMPLETE", "zsh_complete")

    warnings: list[str] = []
    monkeypatch.setattr(ui, "display_warning", warnings.append)

    group = PluginAwareLazyGroup("cli")
    group.list_commands(click.Context(group))

    assert warnings == []


def test_broken_plugin_registry_degrades_to_a_warning(monkeypatch) -> None:
    """A plugin blowing up must not take `--help` or an unknown command down.

    Plugin code is third-party and resolved at runtime, and it now runs inside
    command resolution, i.e. on every `--help` and every unknown command name.
    """
    from ggshield.core import ui

    registry = mock.MagicMock()
    registry.get_commands.side_effect = RuntimeError("plugin exploded")
    _patch_registry(monkeypatch, registry)

    warnings: list[str] = []
    monkeypatch.setattr(ui, "display_warning", warnings.append)

    group = PluginAwareLazyGroup("cli", commands={"auth": click.Command("auth")})

    # Both paths that load plugins keep working.
    assert group.list_commands(click.Context(group)) == ["auth"]
    group._plugins_merged = False
    assert group.get_command(click.Context(group), "missing") is None

    assert any("plugin exploded" in w for w in warnings)


def test_plugin_load_error_is_reported(monkeypatch) -> None:
    """A loader that gave up entirely is surfaced, not just logged.

    load_plugin_registry() swallows the failure to keep the CLI alive, and
    logging is still disabled while commands are resolved, so without this the
    user is never told why every plugin command vanished.
    """
    from ggshield.core import ui
    from ggshield.core.plugin.registry import PluginRegistry

    _patch_registry(monkeypatch, PluginRegistry())
    monkeypatch.setattr(
        "ggshield.core.plugin.hooks.get_plugin_load_error",
        lambda: "enterprise config is unreadable",
    )

    warnings: list[str] = []
    monkeypatch.setattr(ui, "display_warning", warnings.append)

    group = PluginAwareLazyGroup("cli")
    group.list_commands(click.Context(group))

    assert any("enterprise config is unreadable" in w for w in warnings)


def test_no_warning_when_no_failures(monkeypatch) -> None:
    from ggshield.core import ui
    from ggshield.core.plugin.registry import PluginRegistry

    _patch_registry(monkeypatch, PluginRegistry())

    warnings: list[str] = []
    monkeypatch.setattr(ui, "display_warning", warnings.append)

    group = PluginAwareLazyGroup("cli")
    assert group.get_command(click.Context(group), "missing") is None

    assert warnings == []


def test_main_warns_then_click_rejects_unknown_plugin_command(
    monkeypatch, capsys
) -> None:
    """End to end: the warning prints AND Click still rejects the missing command."""
    import ggshield.__main__ as main_module
    from ggshield.core.plugin.registry import PluginRegistry

    registry = PluginRegistry()
    registry.record_load_failure("machine_scan", "error relocating libsatori.so")
    _patch_registry(monkeypatch, registry)
    monkeypatch.setattr(main_module, "force_utf8_output", lambda: None)
    monkeypatch.setattr(main_module, "setup_truststore", lambda: None)

    with pytest.raises(SystemExit):
        main_module.main(["machine", "scan"])

    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "machine_scan" in combined
    assert "No such command" in combined
