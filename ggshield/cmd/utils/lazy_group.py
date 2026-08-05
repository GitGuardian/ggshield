"""Lazy click groups: subcommands are imported only when actually resolved.

Every ggshield invocation used to import all 12 top-level command groups (and
run plugin discovery), so `ggshield secret scan pre-commit` paid for `hmsl`,
`honeytoken`, `auth`, ... Declaring subcommands as "module:attr" strings defers
each import to the moment Click resolves that name.

The strings are invisible to PyInstaller's static analysis: the frozen binary
relies on `--collect-submodules ggshield` plus the generated command-tree smoke
check in scripts/build-os-packages/build-os-packages to guarantee every command
still resolves from the bundle.
"""

import importlib
import os
from typing import Any, Dict, List, Optional

import click

from ggshield.core import ui


class LazyGroup(click.Group):
    """A click Group whose subcommands can be declared as "module:attr" strings
    and are imported only when resolved (canonical click lazy-loading pattern).

    `list_commands()` deliberately does not import anything, so listing names
    (shell completion) is free. `--help` still shows the short help of every
    subcommand, because Click's help formatter calls `get_command()` for each
    listed name -- help is the one slow path, which is fine.

    Use this class for *nested* groups (e.g. `secret scan`), and
    PluginAwareLazyGroup for top-level ones. Plugins contribute top-level
    commands only, so a nested group has nothing to merge; making it
    plugin-aware would just pay for plugin discovery (including wheel signature
    verification) on `--help` and on every unknown subcommand, and would let a
    plugin group that happens to share a nested group's name leak its
    subcommands in there.
    """

    def __init__(
        self,
        *args: Any,
        lazy_commands: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.lazy_commands: Dict[str, str] = lazy_commands or {}

    def list_commands(self, ctx: click.Context) -> List[str]:
        return sorted(set(self.lazy_commands) | set(self.commands))

    def get_command(self, ctx: click.Context, cmd_name: str) -> Optional[click.Command]:
        cmd = super().get_command(ctx, cmd_name)
        if cmd is None and cmd_name in self.lazy_commands:
            cmd = self.load_lazy_command(cmd_name)
        return cmd

    def load_lazy_command(self, name: str) -> click.Command:
        spec = self.lazy_commands[name]
        module_name, _, attr = spec.partition(":")
        if not module_name or not attr:
            raise ValueError(
                f"Invalid lazy command spec for '{name}': {spec!r}, expected 'module:attr'"
            )
        cmd = getattr(importlib.import_module(module_name), attr)
        # Cache it, so later lookups (and plugin merges) see it in self.commands
        self.add_command(cmd, name)
        return cmd


def _merge_subcommands(
    target: click.Group, source: click.Group, warnings: List[str]
) -> None:
    """Merge `source`'s subcommands into `target`, never overriding an existing
    one (a plugin must not be able to silently replace a built-in command).
    Lazy subcommands count as existing even though they are not imported yet.

    Conflicts warn instead of raising: `source` comes from a third-party plugin
    wheel resolved at runtime, so a conflict is not necessarily a ggshield bug
    we would catch during dev, and an installed plugin must never be able to
    make the whole CLI unusable."""
    lazy: Dict[str, str] = getattr(target, "lazy_commands", {})
    for sub_name, sub_cmd in source.commands.items():
        if target.commands.get(sub_name) is sub_cmd:
            # Already merged: the root group and `target` itself both merge the
            # same plugin group, so the second pass must stay silent instead of
            # reporting the command it just added as a conflict.
            continue
        if sub_name in target.commands or sub_name in lazy:
            warnings.append(
                f"Skipping plugin subcommand '{source.name} {sub_name}' because it "
                "conflicts with an existing command"
            )
            continue
        target.add_command(sub_cmd, sub_name)


def add_or_merge_plugin_command(
    root: click.Group, command: click.Command, warnings: List[str]
) -> None:
    """Add a plugin command to the CLI, merging into a built-in group on conflict.

    A plugin contributes a top-level command. If its name is free it is added
    as-is. If it collides with a built-in we used to skip it entirely, which
    broke plugins (e.g. ``machine_scan``) that contribute subcommands of a
    namespace ggshield also owns built-in (``machine``). So when both the
    existing command and the plugin command are groups, we merge the plugin's
    subcommands into the built-in group rather than dropping them. Overlapping
    subcommand names are skipped so a plugin can never silently override a
    built-in subcommand.
    """
    name = command.name
    existing = root.commands.get(name) if name else None
    if existing is None and isinstance(root, LazyGroup) and name in root.lazy_commands:
        # Force-load the built-in, otherwise the plugin would shadow it.
        existing = root.load_lazy_command(name)

    if existing is None:
        root.add_command(command)
        return

    if isinstance(existing, click.Group) and isinstance(command, click.Group):
        _merge_subcommands(existing, command, warnings)
        return

    warnings.append(
        f"Skipping plugin command '{name}' because it conflicts with an "
        "existing command"
    )


class PluginAwareLazyGroup(LazyGroup):
    """LazyGroup that loads plugins on demand instead of on every invocation.

    Plugin discovery (which includes wheel signature verification) runs only
    when it can change the outcome:
    - a command name misses both the built-in and the lazy map, or
    - list_commands() runs, i.e. `--help`, so help output is unchanged.

    ``plugin_scope=None`` is the root CLI group: plugin commands are added at
    top level (merging groups on name conflicts). ``plugin_scope="machine"``
    merges the subcommands of the plugin's ``machine`` group into this group.

    Every built-in top-level group uses this cls with ``plugin_scope`` set to
    its own name: the root group resolves them from ``_LAZY_COMMANDS`` without
    loading plugins, so a group that is a plain LazyGroup would silently drop
    the subcommands of a same-named plugin group. New top-level groups must do
    the same; tests/unit/cmd/test_lazy_commands.py enforces it.
    """

    def __init__(
        self, *args: Any, plugin_scope: Optional[str] = None, **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)
        self.plugin_scope = plugin_scope
        self._plugins_merged = False

    def _ensure_plugins(self) -> None:
        if self._plugins_merged:
            return
        self._plugins_merged = True

        warnings: List[str] = []
        load_failures: Dict[str, str] = {}
        try:
            # Function-local import: keeps the plugin loader (and the enterprise
            # config it reads) off the fast path.
            from ggshield.core.plugin.hooks import (
                get_plugin_load_error,
                load_plugin_registry,
            )

            registry = load_plugin_registry()
            load_error = get_plugin_load_error()
            if load_error:
                warnings.append(
                    f"Failed to load plugins: {load_error}. Plugin commands are "
                    "unavailable; run `ggshield plugin list` for status."
                )
            for cmd in registry.get_commands():
                if not cmd.name:
                    warnings.append("Skipping unnamed plugin command")
                elif self.plugin_scope is None:
                    add_or_merge_plugin_command(self, cmd, warnings)
                elif cmd.name == self.plugin_scope and isinstance(cmd, click.Group):
                    _merge_subcommands(self, cmd, warnings)
            load_failures = registry.get_load_failures()
        except Exception as exc:
            # Everything above runs third-party code resolved at runtime (plugin
            # discovery, and importing the built-in a plugin group collides
            # with). A plugin must never be able to break `--help` or the error
            # for an unknown command, which is every path that lands here, so a
            # failure degrades to a warning as it did before commands were
            # resolved lazily.
            warnings.append(f"Failed to register plugin commands: {exc}")

        # _GGSHIELD_COMPLETE is Click's completion protocol variable
        # (_<PROG_NAME>_COMPLETE). The publisher is the user's shell: the
        # completion function Click generates -- installed with e.g.
        # `eval "$(_GGSHIELD_COMPLETE=bash_source ggshield)"` -- re-invokes
        # ggshield with it set to ask for candidates. cli.main() has not
        # consumed it yet when completion triggers list_commands(), so check it
        # here: these warnings would otherwise be parsed as completion
        # candidates.
        if "_GGSHIELD_COMPLETE" in os.environ:
            return
        # A failed load leaves the command unregistered, so Click rejects it as
        # unknown; warn here or the user never learns why it is missing.
        for name, reason in load_failures.items():
            ui.display_warning(
                f"Plugin '{name}' is enabled but failed to load: {reason}. Its "
                "commands are unavailable; run `ggshield plugin list` for status."
            )
        for msg in warnings:
            ui.display_warning(msg)

    def get_command(self, ctx: click.Context, cmd_name: str) -> Optional[click.Command]:
        cmd = super().get_command(ctx, cmd_name)
        if cmd is None:
            self._ensure_plugins()
            cmd = super().get_command(ctx, cmd_name)
        return cmd

    def list_commands(self, ctx: click.Context) -> List[str]:
        self._ensure_plugins()
        return super().list_commands(ctx)
