import os
import subprocess
import sys
from typing import Optional

import click

from .git_shell import check_git_dir, check_git_installed


@click.command(context_settings={"ignore_unknown_options": True})
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["local", "global"]),
    help="Hook installation mode",
    required=True,
)
@click.option("--force", "-f", is_flag=True, help="Force override")
def install(mode: str, force: bool) -> int:
    """ Command to install a pre-commit hook (local or global). """
    return_code = install_global(force) if mode == "global" else install_local(force)
    sys.exit(return_code)


def install_global(force: bool) -> int:
    """ Global pre-commit hook installation. """
    check_git_installed()
    hook_dir_path = get_global_hook_dir_path()

    if not hook_dir_path:
        hook_dir_path = os.path.expanduser("~/.git/hooks")
        subprocess.run(["git", "config", "--global", "core.hooksPath", hook_dir_path])

    return create_hook(hook_dir_path, force)


def get_global_hook_dir_path() -> Optional[str]:
    """ Return the default hooks path (if it exists). """
    with subprocess.Popen(
        ["git", "config", "--global", "--get", "core.hooksPath"], stdout=subprocess.PIPE
    ) as process:
        if process.returncode:
            return None

        return os.path.expanduser(
            click.format_filename(process.communicate()[0].decode("utf-8")).strip()
        )


def install_local(force: bool) -> int:
    """ Local pre-commit hook installation. """
    check_git_dir()
    return create_hook(".git/hooks", force)


def create_hook(hook_dir_path: str, force: bool) -> int:
    """Create hook directory (if needed) and pre-commit file. """
    os.makedirs(hook_dir_path, exist_ok=True)
    hook_path = "{}/pre-commit".format(hook_dir_path)

    if os.path.isdir(hook_path):
        raise click.ClickException("{} is a directory.".format(hook_path))

    if os.path.isfile(hook_path) and not force:
        raise click.ClickException(
            "{} already exists. Use --force to override.".format(hook_path)
        )

    with open(hook_path, "w") as f:
        f.write("#!/bin/bash\n\nggshield scan -m pre-commit\n")
        os.chmod(hook_path, 0o700)

    click.echo(
        "pre-commit successfully added in {}".format(
            click.style(hook_path, fg="yellow", bold=True)
        )
    )

    return 0
