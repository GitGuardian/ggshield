"""Every lazily-declared command must actually resolve.

Lazy commands are declared as "module:attr" strings, so a typo or a moved
symbol is invisible until a user runs that exact command (and in the frozen
binary, until PyInstaller drops the module). This walks the whole command tree
and resolves every lazy entry.
"""

import click

from ggshield.__main__ import _LAZY_COMMANDS, cli
from ggshield.cmd.utils.lazy_group import LazyGroup, PluginAwareLazyGroup


def test_every_lazy_command_resolves() -> None:
    """GIVEN the ggshield command tree
    WHEN every lazy "module:attr" entry is resolved
    THEN each yields a click command registered under its name
    """
    checked: set[str] = set()

    def walk(group: click.Group, path: str) -> None:
        if isinstance(group, LazyGroup):
            for name in list(group.lazy_commands):
                cmd = group.load_lazy_command(name)
                assert isinstance(cmd, click.Command), f"{path} {name}"
                assert group.commands[name] is cmd, f"{path} {name}"
                checked.add(f"{path} {name}")
        # Resolving a group reveals its own lazy subcommands, so recurse after.
        for name, cmd in list(group.commands.items()):
            if isinstance(cmd, click.Group):
                walk(cmd, f"{path} {name}")

    walk(cli, "ggshield")

    # Guard against the walk silently checking nothing.
    assert "ggshield secret" in checked
    assert "ggshield secret scan ai-hook" in checked


def test_top_level_groups_accept_plugin_merges() -> None:
    """GIVEN the built-in top-level command groups
    WHEN they are resolved from the root group (which does not load plugins)
    THEN each is plugin-aware and scoped to its own name

    A plain LazyGroup here would silently drop the subcommands of a plugin group
    sharing its name, because the root only loads plugins on a name miss.
    """
    ctx = click.Context(cli)

    for name in _LAZY_COMMANDS:
        cmd = cli.get_command(ctx, name)
        if not isinstance(cmd, click.Group):
            continue  # a plain command cannot be a merge target
        assert isinstance(cmd, PluginAwareLazyGroup), name
        assert cmd.plugin_scope == name, name


def test_list_commands_does_not_import_anything() -> None:
    """GIVEN a lazy group whose target module does not exist
    WHEN its commands are listed
    THEN listing succeeds, proving list_commands() imports nothing
    """
    group = LazyGroup("cli", lazy_commands={"nope": "ggshield_no_such_module:cmd"})

    assert group.list_commands(click.Context(group)) == ["nope"]
