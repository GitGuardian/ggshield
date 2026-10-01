import sys
from typing import Dict, Iterator, List, Tuple

import click
import pytest
from click.testing import CliRunner

from ggshield.__main__ import cli
from ggshield.core.errors import ExitCode
from ggshield.utils.git_shell import EMPTY_SHA


GIT_MODULES = ("ggshield.utils.git_shell", "ggshield.core.git_hooks")

SHA = "a" * 40


def _walk(
    group: click.Group, ctx: click.Context
) -> Iterator[Tuple[str, click.Command]]:
    for name in group.list_commands(ctx):
        command = group.get_command(ctx, name)
        if command is None:
            continue
        sub_ctx = click.Context(command, info_name=name, parent=ctx)
        if isinstance(command, click.Group):
            yield from _walk(command, sub_ctx)
        else:
            yield sub_ctx.command_path, command


def _commands() -> Dict[str, click.Command]:
    return dict(_walk(cli, click.Context(cli, info_name="ggshield")))


def _imports_git(command: click.Command) -> bool:
    assert command.callback is not None
    module = sys.modules[command.callback.__module__]
    return any(
        getattr(value, "__module__", getattr(value, "__name__", "")).startswith(
            GIT_MODULES
        )
        for value in vars(module).values()
    )


def test_every_command_importing_git_helpers_declares_its_git_usage():
    """
    GIVEN the whole command tree
    WHEN a command's module imports from the git helper modules
    THEN the command declares how it uses git
    """
    undeclared = [
        path
        for path, command in _commands().items()
        if _imports_git(command) and getattr(command, "git_usage", None) is None
    ]
    assert undeclared == []


@pytest.mark.parametrize(
    ("command_path", "args", "stdin"),
    (
        ("secret scan pre-commit", [], None),
        ("secret scan pre-push", [], f"refs/heads/main {SHA} refs/heads/main {SHA}\n"),
        ("secret scan pre-receive", [], f"{SHA} {SHA} refs/heads/main\n"),
        ("secret scan ci", [], None),
        ("secret scan commit-range", ["HEAD~1...HEAD"], None),
        ("secret scan changes", [], None),
        ("secret scan repo", ["https://example.com/repo.git"], None),
        ("install", ["-m", "global", "-t", "pre-commit"], None),
        ("secret scan path", ["--use-gitignore", "-r", "-y", "."], None),
    ),
)
def test_command_needing_git_fails_cleanly_without_it(
    no_git, cli_fs_runner: CliRunner, command_path: str, args: List[str], stdin
):
    """
    GIVEN git cannot be found
    WHEN a command reaches a feature that needs git
    THEN it prints the git error with the command path and exits 128, no traceback
    """
    result = cli_fs_runner.invoke(
        cli, command_path.split() + args, input=stdin, prog_name="ggshield"
    )
    assert result.exit_code == ExitCode.UNEXPECTED_ERROR, result.output
    assert f"`ggshield {command_path}` requires git: no git." in result.output
    assert "Traceback" not in result.output
    assert "--verbose" not in result.output


@pytest.mark.parametrize(
    ("args", "stdin", "env"),
    (
        (["secret", "scan", "pre-commit"], None, {"SKIP": "ggshield"}),
        (
            ["secret", "scan", "pre-push"],
            f"refs/heads/main {SHA} refs/heads/main {SHA}\n",
            {"SKIP": "ggshield"},
        ),
        (["secret", "scan", "pre-push"], "", {}),
        (
            ["secret", "scan", "pre-push"],
            f"refs/heads/gone {EMPTY_SHA} refs/heads/gone {SHA}\n",
            {},
        ),
        (
            ["secret", "scan", "pre-receive"],
            f"{SHA} {SHA} refs/heads/main\n",
            {"GIT_PUSH_OPTION_COUNT": "1", "GIT_PUSH_OPTION_0": "breakglass"},
        ),
        (["secret", "scan", "pre-receive"], f"{SHA} {EMPTY_SHA} refs/heads/gone\n", {}),
    ),
    ids=(
        "pre-commit SKIP",
        "pre-push SKIP",
        "pre-push nothing to push",
        "pre-push branch deletion",
        "pre-receive breakglass",
        "pre-receive branch deletion",
    ),
)
def test_hook_early_exits_do_not_need_git(
    no_git, cli_fs_runner: CliRunner, args: List[str], stdin, env
):
    """
    GIVEN git cannot be found
    WHEN a hook is asked to let the operation through, or has nothing to scan
    THEN it exits 0 without looking for git
    """
    result = cli_fs_runner.invoke(cli, args, input=stdin, env=env)
    assert result.exit_code == ExitCode.SUCCESS, result.output
    assert "requires git" not in result.output
