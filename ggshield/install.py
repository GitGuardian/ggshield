import os
import subprocess
import sys
from typing import Optional

import click

from .git_shell import GIT_PATH, check_git_dir, check_git_installed


@click.command(context_settings={"ignore_unknown_options": True})
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["local", "global"]),
    help="Hook installation mode",
    required=True,
)
@click.option(
    "--hook-type",
    "-t",
    type=click.Choice(["pre-commit", "pre-push"]),
    help="Type of hook to install",
    default="pre-commit",
)
@click.option("--force", "-f", is_flag=True, help="Force override")
@click.option("--append", "-a", is_flag=True, help="Append to existing script")
def install(mode: str, hook_type: str, force: bool, append: bool) -> int:
    """Command to install a pre-commit or pre-push hook (local or global)."""
    return_code = (
        install_global(hook_type=hook_type, force=force, append=append)
        if mode == "global"
        else install_local(hook_type=hook_type, force=force, append=append)
    )
    sys.exit(return_code)


def install_global(hook_type: str, force: bool, append: bool) -> int:
    """Global pre-commit/pre-push hook installation."""
    check_git_installed()
    hook_dir_path = get_global_hook_dir_path()

    if not hook_dir_path:
        hook_dir_path = os.path.expanduser("~/.git/hooks")
        subprocess.run(
            [GIT_PATH, "config", "--global", "core.hooksPath", hook_dir_path]
        )

    return create_hook(
        hook_dir_path=hook_dir_path,
        force=force,
        local_hook_support=True,
        hook_type=hook_type,
        append=append,
    )


def get_global_hook_dir_path() -> Optional[str]:
    """Return the default hooks path (if it exists)."""
    with subprocess.Popen(
        [GIT_PATH, "config", "--global", "--get", "core.hooksPath"],
        stdout=subprocess.PIPE,
    ) as process:
        if process.returncode:
            return None

        return os.path.expanduser(
            click.format_filename(process.communicate()[0].decode("utf-8")).strip()
        )


def install_local(hook_type: str, force: bool, append: bool) -> int:
    """Local pre-commit/pre-push hook installation."""
    check_git_dir()
    return create_hook(
        hook_dir_path=".git/hooks",
        force=force,
        local_hook_support=False,
        hook_type=hook_type,
        append=append,
    )


def create_hook(
    hook_dir_path: str,
    force: bool,
    local_hook_support: bool,
    hook_type: str,
    append: bool,
) -> int:
    """Create hook directory (if needed) and pre-commit/pre-push file."""
    os.makedirs(hook_dir_path, exist_ok=True)
    hook_path = f"{hook_dir_path}/{hook_type}"

    if os.path.isdir(hook_path):
        raise click.ClickException(f"{hook_path} is a directory.")

    if os.path.isfile(hook_path) and not (force or append):
        raise click.ClickException(
            f"{hook_path} already exists."
            " Use --force to override or --append to add to current script"
        )

    local_hook_str = ""
    if local_hook_support:
        local_hook_str = f"""
if [[ -f .git/hooks/{hook_type} ]]; then
    if ! .git/hooks/{hook_type} $@; then
        echo 'Local {hook_type} hook failed, please see output above'
        exit 1
    fi
fi
"""

    mode = "a" if os.path.exists(hook_path) and append else "w"

    with open(hook_path, mode) as f:
        if mode == "w":
            f.write("#!/bin/bash\n")

        f.write(f"\n{local_hook_str}\nggshield scan {hook_type}\n")
        os.chmod(hook_path, 0o700)

    click.echo(
        f"{hook_type} successfully added in"
        f" {click.style(hook_path, fg='yellow', bold=True)}"
    )

    return 0
