import json
import os
import subprocess
from pathlib import Path
from typing import Any, Optional

import click
from click import UsageError

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.core.claude_code import CLAUDE_CODE_EVENT_CONFIGS
from ggshield.core.cursor import CURSOR_EVENT_COMMANDS
from ggshield.core.dirs import get_data_dir, get_user_home_dir
from ggshield.core.errors import UnexpectedError
from ggshield.utils.git_shell import check_git_dir, git

# This snippet is used by the global hook to call the hook defined in the
# repository, if it exists.
# Because of #467, we must use /bin/sh as a shell, so the shell code must
# not make use of any Bash extension, such as double square brackets in
# `if` statements.
LOCAL_HOOK_SNIPPET = """
if [ -f .git/hooks/{hook_type} ]; then
    if ! .git/hooks/{hook_type} "$@"; then
        echo 'Local {hook_type} hook failed, please see output above'
        exit 1
    fi
fi
"""


@click.command(context_settings={"ignore_unknown_options": True})
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["local", "global"]),
    help="Hook installation mode.",
    required=True,
)
@click.option(
    "--hook-type",
    "-t",
    type=click.Choice(["pre-commit", "pre-push", "cursor", "claude-code"]),
    help="Type of hook to install.",
    default="pre-commit",
)
@click.option("--force", "-f", is_flag=True, help="Overwrite any existing hook script.")
@click.option("--append", "-a", is_flag=True, help="Append to existing script.")
@add_common_options()
def install_cmd(
    mode: str, hook_type: str, force: bool, append: bool, **kwargs: Any
) -> int:
    """
    Installs ggshield as a pre-commit, pre-push, Cursor, or Claude Code hook.

    The `install` command installs ggshield as a git pre-commit or pre-push hook, either
    for the current repository (locally) or for all repositories (globally).
    It can also install ggshield as a Cursor IDE or Claude Code agent hook.
    """
    if hook_type == "cursor":
        return_code = (
            install_cursor_global(force=force)
            if mode == "global"
            else install_cursor_local(force=force)
        )
    elif hook_type == "claude-code":
        return_code = (
            install_claude_code_global(force=force)
            if mode == "global"
            else install_claude_code_local(force=force)
        )
    else:
        return_code = (
            install_global(hook_type=hook_type, force=force, append=append)
            if mode == "global"
            else install_local(hook_type=hook_type, force=force, append=append)
        )
    return return_code


def install_global(hook_type: str, force: bool, append: bool) -> int:
    """Global pre-commit/pre-push hook installation."""
    hook_dir_path = get_global_hook_dir_path()

    if not hook_dir_path:
        hook_dir_path = get_default_global_hook_dir_path()
        git(
            ["config", "--global", "core.hooksPath", str(hook_dir_path)],
            ignore_git_config=False,
        )

    return create_hook(
        hook_dir_path=hook_dir_path,
        force=force,
        local_hook_support=True,
        hook_type=hook_type,
        append=append,
    )


def get_default_global_hook_dir_path() -> Path:
    """
    Returns the directory in which ggshield creates its global hooks
    """
    return get_data_dir() / "git-hooks"


def get_global_hook_dir_path() -> Optional[Path]:
    """Return the default hooks path defined in git global config (if it exists)."""
    try:
        out = git(
            ["config", "--global", "--get", "core.hooksPath"], ignore_git_config=False
        )
    except subprocess.CalledProcessError:
        return None
    return Path(click.format_filename(out)).expanduser()


def install_local(hook_type: str, force: bool, append: bool) -> int:
    """Local pre-commit/pre-push hook installation."""
    check_git_dir()
    hook_dir_path = get_local_hook_dir_path()
    return create_hook(
        hook_dir_path=hook_dir_path,
        force=force,
        local_hook_support=False,
        hook_type=hook_type,
        append=append,
    )


def get_local_hook_dir_path() -> Path:
    """
    Return the directory where local hooks should be installed.

    If core.hooksPath is configured, honor it and detect Husky-managed repositories
    to avoid overwriting Husky's shim scripts.
    """
    hooks_path = get_git_local_hooks_path()
    if hooks_path is None:
        return Path(".git/hooks")

    if is_husky_hooks_path(hooks_path):
        return hooks_path.parent

    return hooks_path


def get_git_local_hooks_path() -> Optional[Path]:
    """Return the hooks path defined in the repository config, if any."""
    try:
        out = git(
            ["config", "--local", "--get", "core.hooksPath"], ignore_git_config=False
        )
    except subprocess.CalledProcessError:
        return None
    return Path(click.format_filename(out)).expanduser()


def is_husky_hooks_path(path: Path) -> bool:
    """Detect Husky-generated hooks directories (.husky/_)."""
    try:
        return path.name == "_" and path.parent.name == ".husky"
    except IndexError:
        return False


def create_hook(
    hook_dir_path: Path,
    force: bool,
    local_hook_support: bool,
    hook_type: str,
    append: bool,
) -> int:
    """Create hook directory (if needed) and pre-commit/pre-push file."""
    hook_dir_path.mkdir(parents=True, exist_ok=True)
    hook_path = hook_dir_path / hook_type

    if hook_path.is_dir():
        raise UsageError(f"{hook_path} is a directory.")

    if hook_path.is_file() and not (force or append):
        raise UnexpectedError(
            f"{hook_path} already exists."
            " Use --force to override or --append to add to current script"
        )

    if append and not hook_path.exists():
        # If the file does not exist, we must add the shebang, even if we were
        # called with --append.
        append = False

    with hook_path.open("a" if append else "w") as f:
        if not append:
            f.write("#!/bin/sh\n")

        if local_hook_support:
            f.write(LOCAL_HOOK_SNIPPET.format(hook_type=hook_type))
            f.write("\n")

        f.write(f'ggshield secret scan {hook_type} "$@"\n')
        os.chmod(hook_path, 0o700)

    click.echo(
        f"{hook_type} successfully added in"
        f" {click.style(hook_path, fg='yellow', bold=True)}"
    )

    return 0


def install_cursor_global(force: bool) -> int:
    """Global Cursor hooks installation (~/.cursor/hooks.json)."""
    hooks_path = get_user_home_dir() / ".cursor" / "hooks.json"
    return create_cursor_hooks(hooks_path=hooks_path, force=force)


def install_cursor_local(force: bool) -> int:
    """Local Cursor hooks installation (.cursor/hooks.json)."""
    hooks_path = Path(".cursor") / "hooks.json"
    return create_cursor_hooks(hooks_path=hooks_path, force=force)


def create_cursor_hooks(hooks_path: Path, force: bool) -> int:
    """
    Create or update the Cursor hooks.json file with ggshield hooks.

    Args:
        hooks_path: Path to the hooks.json file
        force: If True, replace existing ggshield hooks with new command

    Returns:
        0 on success
    """
    # Load existing config or create new one
    existing_config: dict = {"version": 1, "hooks": {}}
    if hooks_path.exists():
        try:
            with hooks_path.open("r", encoding="utf-8") as f:
                existing_config = json.load(f)
        except json.JSONDecodeError as e:
            raise UnexpectedError(
                f"Failed to parse {hooks_path}: {e}. "
                "Please fix or remove the file before installing hooks."
            )

    hooks = existing_config.setdefault("hooks", {})

    # Track what we did for reporting
    added_count = 0
    already_present_count = 0

    # Add ggshield hooks for each event type that has commands defined
    for event_type, commands in CURSOR_EVENT_COMMANDS.items():
        event_name = event_type.value
        hook_list = hooks.setdefault(event_name, [])

        # Check if ggshield is already present in this hook list
        ggshield_present = any(
            "ggshield" in hook.get("command", "") for hook in hook_list
        )

        if ggshield_present:
            if force:
                # Remove existing ggshield hooks and add the new ones
                hook_list[:] = [
                    hook
                    for hook in hook_list
                    if "ggshield" not in hook.get("command", "")
                ]
                for command in commands:
                    hook_list.append({"command": command})
                added_count += len(commands)
            else:
                already_present_count += 1
        else:
            for command in commands:
                hook_list.append({"command": command})
            added_count += len(commands)

    # Ensure parent directory exists
    hooks_path.parent.mkdir(parents=True, exist_ok=True)

    # Write the updated config
    with hooks_path.open("w", encoding="utf-8") as f:
        json.dump(existing_config, f, indent=2)
        f.write("\n")

    # Report what happened
    styled_path = click.style(hooks_path, fg="yellow", bold=True)
    if added_count == 0 and already_present_count > 0:
        click.echo(f"Cursor hooks already installed in {styled_path}")
    elif added_count > 0 and already_present_count > 0:
        click.echo(f"Cursor hooks updated in {styled_path}")
    else:
        click.echo(f"Cursor hooks successfully added in {styled_path}")

    return 0


def install_claude_code_global(force: bool) -> int:
    """Global Claude Code hooks installation (~/.claude/settings.json)."""
    settings_path = get_user_home_dir() / ".claude" / "settings.json"
    return create_claude_code_hooks(settings_path=settings_path, force=force)


def install_claude_code_local(force: bool) -> int:
    """Local Claude Code hooks installation (.claude/settings.json)."""
    settings_path = Path(".claude") / "settings.json"
    return create_claude_code_hooks(settings_path=settings_path, force=force)


def create_claude_code_hooks(settings_path: Path, force: bool) -> int:
    """
    Create or update the Claude Code settings.json file with ggshield hooks.

    Claude Code hooks have a different structure than Cursor hooks:
    - Hooks are organized by event type (PreToolUse, PostToolUse, UserPromptSubmit)
    - PreToolUse/PostToolUse use matchers to filter by tool name
    - Each matcher can have multiple hooks

    Args:
        settings_path: Path to the settings.json file
        force: If True, replace existing ggshield hooks with new command

    Returns:
        0 on success
    """
    # Load existing config or create new one
    existing_config: dict = {}
    if settings_path.exists():
        try:
            with settings_path.open("r", encoding="utf-8") as f:
                existing_config = json.load(f)
        except json.JSONDecodeError as e:
            raise UnexpectedError(
                f"Failed to parse {settings_path}: {e}. "
                "Please fix or remove the file before installing hooks."
            )

    hooks = existing_config.setdefault("hooks", {})

    # Track what we did for reporting
    added_count = 0
    already_present_count = 0

    # Add ggshield hooks for each event type
    for event_type, hook_configs in CLAUDE_CODE_EVENT_CONFIGS.items():
        event_name = event_type.value
        hook_list = hooks.setdefault(event_name, [])

        for hook_config in hook_configs:
            matcher = hook_config.get("matcher")

            # Check if ggshield is already present for this matcher
            ggshield_present = False
            for existing_hook in hook_list:
                existing_matcher = existing_hook.get("matcher")
                if existing_matcher == matcher:
                    # Check if any of the hooks contain ggshield
                    for h in existing_hook.get("hooks", []):
                        if "ggshield" in h.get("command", ""):
                            ggshield_present = True
                            break
                elif matcher is None and existing_matcher is None:
                    # For hooks without matchers (like UserPromptSubmit)
                    for h in existing_hook.get("hooks", []):
                        if "ggshield" in h.get("command", ""):
                            ggshield_present = True
                            break

            if ggshield_present:
                if force:
                    # Remove existing ggshield hooks for this matcher
                    for existing_hook in hook_list:
                        existing_matcher = existing_hook.get("matcher")
                        if existing_matcher == matcher:
                            existing_hook["hooks"] = [
                                h
                                for h in existing_hook.get("hooks", [])
                                if "ggshield" not in h.get("command", "")
                            ]
                            # Add the new ggshield hook
                            existing_hook["hooks"].extend(hook_config["hooks"])
                            added_count += 1
                            break
                    else:
                        # Matcher not found, add new entry
                        hook_list.append(hook_config)
                        added_count += 1
                else:
                    already_present_count += 1
            else:
                # Check if we have an existing entry with this matcher
                found_matcher = False
                for existing_hook in hook_list:
                    if existing_hook.get("matcher") == matcher:
                        # Add to existing matcher entry
                        existing_hook.setdefault("hooks", []).extend(hook_config["hooks"])
                        added_count += 1
                        found_matcher = True
                        break

                if not found_matcher:
                    # Add new matcher entry
                    hook_list.append(hook_config)
                    added_count += 1

    # Ensure parent directory exists
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    # Write the updated config
    with settings_path.open("w", encoding="utf-8") as f:
        json.dump(existing_config, f, indent=2)
        f.write("\n")

    # Report what happened
    styled_path = click.style(settings_path, fg="yellow", bold=True)
    if added_count == 0 and already_present_count > 0:
        click.echo(f"Claude Code hooks already installed in {styled_path}")
    elif added_count > 0 and already_present_count > 0:
        click.echo(f"Claude Code hooks updated in {styled_path}")
    else:
        click.echo(f"Claude Code hooks successfully added in {styled_path}")

    return 0
