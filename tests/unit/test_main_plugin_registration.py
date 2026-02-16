"""Tests for plugin command registration in __main__.py."""

from unittest import mock

import click


def test_register_plugin_commands_skips_conflicts(monkeypatch) -> None:
    """Plugin commands must not override built-in commands."""
    import ggshield.__main__ as main_module

    plugin_conflicting_cmd = click.Command("auth")
    plugin_new_cmd = click.Command("plugin-extra")

    mock_registry = mock.MagicMock()
    mock_registry.get_commands.return_value = [plugin_conflicting_cmd, plugin_new_cmd]

    mock_cli = mock.MagicMock()
    mock_cli.commands = {
        "auth": click.Command("auth"),
        "config": click.Command("config"),
    }

    deferred_warnings: list[str] = []

    monkeypatch.setattr(main_module, "cli", mock_cli)
    monkeypatch.setattr(main_module, "_deferred_warnings", deferred_warnings)
    monkeypatch.setattr(main_module, "_load_plugins", lambda: mock_registry)

    main_module._register_plugin_commands()

    mock_cli.add_command.assert_called_once_with(plugin_new_cmd)
    assert any("conflicts with an existing command" in msg for msg in deferred_warnings)
