from unittest import mock

import click
import pytest

from ggshield.utils.click.default_command_group import DefaultCommandGroup


@pytest.fixture
def group_with_default():
    group = DefaultCommandGroup()

    @group.command(default_command=True)
    def run():
        pass

    return group


def test_no_such_command_redirects_to_default(group_with_default):
    """
    GIVEN a DefaultCommandGroup with a default command
    WHEN resolve_command raises 'No such command'
    THEN the call is redirected to the default command
    """
    ctx = click.Context(group_with_default)
    cmd_name, cmd, _ = group_with_default.resolve_command(ctx, ["unknown"])
    assert cmd_name == group_with_default.default_command


def test_non_no_such_command_error_propagates(group_with_default):
    """
    GIVEN a DefaultCommandGroup with a default command
    WHEN resolve_command raises a UsageError that is NOT 'No such command'
    THEN the error propagates instead of being redirected to the default command
    """
    default_name = group_with_default.default_command
    run_cmd = group_with_default.get_command(None, default_name)
    ambiguous_error = click.UsageError("Command 'r' is ambiguous.")

    with mock.patch.object(
        click.Group,
        "resolve_command",
        side_effect=[ambiguous_error, (default_name, run_cmd, [])],
    ):
        ctx = click.Context(group_with_default)
        with pytest.raises(click.UsageError, match="is ambiguous"):
            group_with_default.resolve_command(ctx, ["r"])
