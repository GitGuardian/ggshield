#!/usr/bin/python3
import os
import re
import sys
import tempfile
import traceback
from contextlib import contextmanager
from typing import List, Union

import click

from .config import load_config
from .git_shell import check_git_dir, shell
from .install import install
from .message import process_scan_result
from .path import get_files_from_paths
from .pygitguardian import GGClient
from .scan import scan_ci, scan_commit_range
from .scannable import Commit, Files


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])


@click.command()
@click.pass_context
@click.argument(
    "paths", nargs=-1, type=click.Path(exists=True, resolve_path=True), required=False
)
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["pre-commit", "ci"]),
    help="Scan mode (pre-commit or ci)",
    required=False,
)
@click.option("--recursive", "-r", is_flag=True, help="Scan directory recursively")
@click.option("--yes", "-y", is_flag=True, help="Confirm recursive scan")
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Display the list of files before recursive scan",
)
@click.option(
    "--exclude",
    type=str,
    help=(
        "A regular expression that matches files and directories that should be "
        "excluded on recursive searches. An empty value means no paths are excluded."
    ),
)
@click.option("--repo", nargs=1, help="Scan Git Repository (repo url)")
def scan(
    ctx: object,
    paths: Union[List, str],
    mode: str,
    recursive: bool,
    exclude: bool,
    yes: bool,
    verbose: bool,
    repo: str,
) -> int:
    """ Command to scan various content. """
    client = ctx.obj["client"]
    return_code = 0

    compiled_exclude = None
    if exclude:
        compiled_exclude = re.compile(exclude)
    elif ctx.obj["config"]["exclude"]:
        compiled_exclude = re.compile(ctx.obj["config"]["exclude"])

    try:
        if mode:
            check_git_dir()
            if mode == "pre-commit":
                return_code = process_scan_result(
                    Commit().scan(
                        client=client,
                        ignored_matches=ctx.obj["config"]["ignored_matches"],
                    )
                )

            elif mode == "ci":
                return_code = scan_ci(
                    client=client,
                    verbose=verbose,
                    ignored_matches=ctx.obj["config"]["ignored_matches"],
                )

            else:
                click.echo(ctx.get_help())

        elif repo:
            try:
                with tempfile.TemporaryDirectory() as tmpdirname:
                    shell(f"git clone {repo} {tmpdirname}")
                    with cd(tmpdirname):
                        scan_commit_range(
                            client=client,
                            commit_range=None,
                            verbose=verbose,
                            all_commits=True,
                            ignored_matches=ctx.obj["config"]["ignored_matches"],
                        )

            except ValueError:
                click.echo(ctx.get_help())

        elif paths:
            files = Files(
                get_files_from_paths(paths, compiled_exclude, recursive, yes, verbose)
            )
            return_code = process_scan_result(
                files.scan(client, ctx.obj["config"]["ignored_matches"])
            )

        else:
            click.echo(ctx.get_help())

    except click.exceptions.Abort:
        return_code = 0
    except Exception as error:
        if verbose:
            traceback.print_exc()
        raise click.ClickException(str(error))

    sys.exit(return_code)


@contextmanager
def cd(newdir):
    prevdir = os.getcwd()
    os.chdir(os.path.expanduser(newdir))
    try:
        yield
    finally:
        os.chdir(prevdir)


@click.group(context_settings=CONTEXT_SETTINGS)
@click.pass_context
def cli(ctx: object):
    token = os.getenv("GITGUARDIAN_API_KEY")
    base_uri = os.getenv("GITGUARDIAN_API_URL")
    if not token:
        raise click.ClickException("GitGuardian Token is needed.")

    ctx.ensure_object(dict)
    ctx.obj["client"] = GGClient(
        token=token, base_uri=base_uri, user_agent="ggshield", timeout=60
    )
    ctx.obj["config"] = load_config()


cli.add_command(scan)
cli.add_command(install)

if __name__ == "__main__":
    cli()
