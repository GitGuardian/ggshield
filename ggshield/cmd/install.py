import os
import subprocess
from pathlib import Path
from typing import Any, Literal, Optional

import click
from click import UsageError

from ggshield.cmd.utils.common_options import add_common_options
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui
from ggshield.core.dirs import get_data_dir, get_system_data_dir
from ggshield.core.errors import UnexpectedError
from ggshield.utils.git_shell import GitError, check_git_dir, get_git_root, git
from ggshield.verticals.ai.installation import (
    AGENTS,
    check_ai_hook_authentication,
    install_hooks,
)


# This snippet is used by the global hook to call the hook defined in the
# repository, if it exists.
# Because of #467, we must use /bin/sh as a shell, so the shell code must
# not make use of any Bash extension, such as double square brackets in
# `if` statements.
LOCAL_HOOK_SNIPPET = """
_ggshield_local_hook=$(git rev-parse --git-common-dir)/hooks/{hook_type}
if [ -f "$_ggshield_local_hook" ]; then
    if ! "$_ggshield_local_hook" "$@"; then
        echo 'Local {hook_type} hook failed, please see output above'
        exit 1
    fi
fi
"""

# The line `create_hook` writes into every ggshield-managed hook script; its presence
# is how we recognize a hook (or hooks dir) as ggshield's own.
GGSHIELD_HOOK_MARKER = "ggshield secret scan"


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
    type=click.Choice(["pre-commit", "pre-push"] + list(AGENTS.keys())),
    help="Type of hook to install.",
    default="pre-commit",
)
@click.option("--force", "-f", is_flag=True, help="Overwrite any existing hook script.")
@click.option("--append", "-a", is_flag=True, help="Append to existing script.")
@add_common_options()
@click.pass_context
def install_cmd(
    ctx: click.Context,
    mode: Literal["local", "global"],
    hook_type: str,
    force: bool,
    append: bool,
    **kwargs: Any,
) -> int:
    """
    Installs ggshield as a pre-commit, pre-push, or AI coding assistant hook.

    The `install` command installs ggshield as a git pre-commit or pre-push hook, either
    for the current repository (locally) or for all repositories (globally).
    It can also install ggshield as an AI coding assistant hook.
    """

    if hook_type in AGENTS:
        ui.display_warning(
            f"`ggshield install -t {hook_type}` is deprecated. Use "
            "`ggshield machine setup` to configure the ggshield AI hook for "
            "every detected assistant at once."
        )
        returncode = install_hooks(name=hook_type, mode=mode, force=force)
        if returncode == 0:
            check_ai_hook_authentication(ContextObj.get(ctx).config)
        return returncode

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


def install_system(hook_type: str, force: bool, append: bool) -> int:
    """System-wide (all users) pre-commit/pre-push hook installation.

    Sets git's ``--system`` ``core.hooksPath`` to a shared, world-readable directory
    so every user on the machine inherits the hook from a single install — the right
    behavior when ``machine setup`` runs as root under an MDM. Requires write access
    to the system git config and data dir (i.e. root).
    """
    hook_dir_path = get_system_hook_dir_path()

    if not hook_dir_path:
        hook_dir_path = get_default_system_hook_dir_path()
        git(
            ["config", "--system", "core.hooksPath", str(hook_dir_path)],
            ignore_git_config=False,
        )

    return create_hook(
        hook_dir_path=hook_dir_path,
        force=force,
        local_hook_support=True,
        hook_type=hook_type,
        append=append,
        world_readable=True,
    )


def get_default_system_hook_dir_path() -> Path:
    """Return the machine-wide directory in which ggshield creates its system hooks."""
    return get_system_data_dir() / "git-hooks"


def get_system_hook_dir_path() -> Optional[Path]:
    """Return the hooks path defined in git system config (if it exists)."""
    try:
        out = git(
            ["config", "--system", "--get", "core.hooksPath"], ignore_git_config=False
        )
    except subprocess.CalledProcessError:
        return None
    return Path(click.format_filename(out)).expanduser()


def get_configured_hook_dir_path() -> Optional[Path]:
    """Return the ``core.hooksPath`` git would actually use in the current context.

    Resolves git's normal precedence (local repo > global user > system). A relative
    ``core.hooksPath`` (e.g. Husky's ``.husky/_``) is resolved against the repository
    root, the way git itself interprets it, so the path is usable regardless of the
    current working directory. Returns ``None`` when no ``core.hooksPath`` is
    configured anywhere (git then uses ``.git/hooks``) or when git cannot be queried,
    so callers — including the gating ``machine doctor`` — never crash on a git error.
    """
    try:
        out = git(["config", "--get", "core.hooksPath"], ignore_git_config=False)
    except (subprocess.CalledProcessError, GitError, OSError):
        return None
    path = Path(click.format_filename(out)).expanduser()
    if not path.is_absolute():
        repo_root = _get_repo_root()
        if repo_root is not None:
            path = repo_root / path
    return path


def _get_repo_root() -> Optional[Path]:
    """Return the working tree root, or ``None`` when git cannot resolve it."""
    try:
        return get_git_root()
    except (GitError, OSError):
        return None


def hook_invokes_ggshield(hook_path: Path) -> bool:
    """Whether ``hook_path`` is an existing hook script that runs ggshield.

    Single source of truth for recognizing a ggshield-managed hook by the marker line
    ``create_hook`` writes. ``errors="ignore"`` only covers decoding, so an unreadable
    file (permissions, a race between the ``is_file`` check and the read, a special
    file) is treated as "not ggshield's" rather than crashing the gating ``doctor``.
    """
    try:
        return hook_path.is_file() and GGSHIELD_HOOK_MARKER in hook_path.read_text(
            errors="ignore"
        )
    except OSError:
        return False


def is_ggshield_hook_dir(hook_dir: Path) -> bool:
    """Whether ``hook_dir`` holds (or, for Husky, sources) ggshield hook scripts.

    For a Husky ``.husky/_`` directory the runnable hook lives in the parent
    ``.husky/`` — that is where ``ggshield install --mode local`` writes its content
    and what Husky's ``_`` wrappers source — so the parent is inspected too.
    """
    candidate_dirs = [hook_dir]
    if is_husky_hooks_path(hook_dir):
        candidate_dirs.append(hook_dir.parent)
    return any(
        hook_invokes_ggshield(directory / hook_type)
        for directory in candidate_dirs
        for hook_type in ("pre-commit", "pre-push")
    )


def get_shadowing_hooks_path() -> Optional[Path]:
    """Return the effective ``core.hooksPath`` if it shadows ggshield's hook.

    Git uses exactly one hooks directory — the most specific ``core.hooksPath`` wins.
    So a repo-local or user-global ``core.hooksPath`` pointing at a non-ggshield
    directory (e.g. Husky's ``.husky/_``) takes precedence over ggshield's
    system/global install, and ggshield's hook never runs in that context. Returns
    that overriding path, or ``None`` when ggshield's hook is the effective one (or no
    ``core.hooksPath`` override is configured at all).
    """
    effective = get_configured_hook_dir_path()
    if effective is None or is_ggshield_hook_dir(effective):
        return None
    return effective


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
    world_readable: bool = False,
) -> int:
    """Create hook directory (if needed) and pre-commit/pre-push file.

    ``world_readable`` makes the directory and hook script readable and executable by
    every user (0755) instead of owner-only (0700) — required for a system-wide
    install, where the hook runs as each committing user.
    """
    hook_dir_path.mkdir(parents=True, exist_ok=True)
    if world_readable:
        # A system-scoped hooks dir must be traversable + readable by all users.
        try:
            os.chmod(hook_dir_path, 0o755)
        except OSError:
            pass
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
        os.chmod(hook_path, 0o755 if world_readable else 0o700)

    click.echo(
        f"{hook_type} successfully added in"
        f" {click.style(hook_path, fg='yellow', bold=True)}"
    )

    return 0
