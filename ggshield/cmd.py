#!/usr/bin/python3
import os
import sys
import traceback
from pathlib import Path
from typing import List, Union

import click
from pygitguardian import GGClient

from .config import Config
from .filter import path_filter_set
from .git_shell import check_git_dir
from .install import install
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
    "--show-secrets",
    is_flag=True,
    default=None,
    help="Show secrets in plaintext instead of hiding them",
)
@click.option(
    "--exit-zero",
    is_flag=True,
    default=None,
    envvar="GITGUARDIAN_EXIT_ZERO",
    help="Always return a 0 (non-error) status code, even if issues are found."
    "The env var GITGUARDIAN_EXIT_ZERO can also be used to set this option",
)
@click.option(
    "--all-policies",
    is_flag=True,
    default=None,
    help="Present fails of all policies (Filenames, FileExtensions, Secret Detection)."
    "By default, only Secret Detection is shown"
    "",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=None,
    help="Display the list of files before recursive scan",
)
@click.option("--repo", nargs=1, help="Scan Git Repository (repo url)")
def scan(
    ctx: click.Context,
    paths: Union[List, str],
    mode: str,
    recursive: bool,
    yes: bool,
    show_secrets: bool,
    exit_zero: bool,
    all_policies: bool,
    verbose: bool,
    repo: str,
) -> int:
    """ Command to scan various content. """
    api_key = os.getenv("GITGUARDIAN_API_KEY")
    base_uri = os.getenv("GITGUARDIAN_API_URL", ctx.obj["config"].api_url)
    if not api_key:
        raise click.ClickException("GitGuardian API Key is needed.")

    client = GGClient(
        api_key=api_key, base_uri=base_uri, user_agent="ggshield", timeout=60
    )
    return_code = 0

    matches_ignore = ctx.obj["config"].matches_ignore
    filter_set = path_filter_set(Path(os.getcwd()), ctx.obj["config"].paths_ignore)
    if show_secrets is None:
        show_secrets = ctx.obj["config"].show_secrets

    if all_policies is None:
        all_policies = ctx.obj["config"].all_policies

    if verbose is None:
        verbose = ctx.obj["config"].verbose

    if exit_zero is None:
        exit_zero = ctx.obj["config"].exit_zero

    try:
        if mode:
            check_git_dir()
            if mode == "pre-commit":
                return_code = scan_pre_commit(
                    client=client,
                    filter_set=filter_set,
                    matches_ignore=matches_ignore,
                    verbose=verbose,
                    all_policies=all_policies,
                    show_secrets=show_secrets,
                )
            elif mode == "ci":
                return_code = scan_ci(
                    client=client,
                    verbose=verbose,
                    filter_set=filter_set,
                    matches_ignore=matches_ignore,
                    all_policies=all_policies,
                    show_secrets=show_secrets,
                )
            else:
                click.echo(ctx.get_help())
        elif repo:
            return_code = scan_repo(
                client=client,
                verbose=verbose,
                repo=repo,
                matches_ignore=matches_ignore,
                all_policies=all_policies,
                show_secrets=show_secrets,
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
                all_policies=all_policies,
                show_secrets=show_secrets,
            )
        else:
            click.echo(ctx.get_help())
    except click.exceptions.Abort:
        return_code = 0
    except Exception as error:
        if verbose:
            traceback.print_exc()
        raise click.ClickException(str(error))

    if exit_zero:
        return_code = 0
    sys.exit(return_code)


@click.group(context_settings=CONTEXT_SETTINGS)
@click.option(
    "-c",
    "--config-path",
    type=click.Path(exists=True, resolve_path=True, file_okay=True, dir_okay=False),
    help="Set a custom config file. Ignores local and global config files.",
)
@click.pass_context
def cli(ctx: click.Context, config_path: str):
    ctx.ensure_object(dict)
    if config_path:
        Config.CONFIG_LOCAL = [config_path]
        Config.CONFIG_GLOBAL = []

    ctx.obj["config"] = Config()


cli.add_command(scan)
cli.add_command(install)

if __name__ == "__main__":
    cli()
