#!/usr/bin/python3
import os
import sys
import traceback
from pathlib import Path
from typing import List, Union

import click

from .config import Config
from .filter import path_filter_set
from .git_shell import check_git_dir
from .install import install
from .pygitguardian import GGClient
from .scan import scan_ci, scan_path, scan_pre_commit, scan_repo


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
@click.option("--repo", nargs=1, help="Scan Git Repository (repo url)")
def scan(
    ctx: object,
    paths: Union[List, str],
    mode: str,
    recursive: bool,
    yes: bool,
    verbose: bool,
    repo: str,
) -> int:
    """ Command to scan various content. """
    token = os.getenv("GITGUARDIAN_API_KEY")
    base_uri = os.getenv("GITGUARDIAN_API_URL")
    if not token:
        raise click.ClickException("GitGuardian Token is needed.")

    client = GGClient(token=token, base_uri=base_uri, user_agent="ggshield", timeout=60)
    return_code = 0

    matches_ignore = ctx.obj["config"].matches_ignore
    filter_set = path_filter_set(Path(os.getcwd()), ctx.obj["config"].paths_ignore)
    try:
        if mode:
            check_git_dir()
            if mode == "pre-commit":
                return_code = scan_pre_commit(
                    client=client,
                    filter_set=filter_set,
                    matches_ignore=matches_ignore,
                    verbose=verbose,
                )
            elif mode == "ci":
                return_code = scan_ci(
                    client=client,
                    verbose=verbose,
                    filter_set=filter_set,
                    matches_ignore=matches_ignore,
                )
            else:
                click.echo(ctx.get_help())
        elif repo:
            return_code = scan_repo(
                client=client,
                verbose=verbose,
                repo=repo,
                matches_ignore=matches_ignore,
            )
        elif paths:
            return_code = scan_path(
                client=client,
                verbose=verbose,
                paths=paths,
                paths_ignore=ctx.obj["config"].paths_ignore,
                recursive=recursive,
                yes=yes,
                matches_ignore=matches_ignore,
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


@click.group(context_settings=CONTEXT_SETTINGS)
@click.pass_context
def cli(ctx: object):
    ctx.ensure_object(dict)
    ctx.obj["config"] = Config()


cli.add_command(scan)
cli.add_command(install)

if __name__ == "__main__":
    cli()
