#!/usr/bin/python3
import os
import sys
from pathlib import Path

import click
from pygitguardian import GGClient

from .ci import ci_cmd
from .config import CONTEXT_SETTINGS, Config
from .dev_scan import path_cmd, precommit_cmd, range_cmd, repo_cmd
from .filter import path_filter_set
from .install import install


@click.group(
    invoke_without_command=True,
    context_settings=CONTEXT_SETTINGS,
    commands={
        "commit-range": range_cmd,
        "pre-commit": precommit_cmd,
        "ci": ci_cmd,
        "path": path_cmd,
        "repo": repo_cmd,
    },
)
@click.option(
    "--mode",
    "-m",
    type=click.Choice(["pre-commit", "ci"]),
    help="Scan mode (pre-commit or ci)",
    required=False,
    hidden=True,
)
@click.option(
    "--show-secrets",
    is_flag=True,
    default=None,
    help="Show secrets in plaintext instead of hiding them.",
)
@click.option(
    "--exit-zero",
    is_flag=True,
    default=None,
    envvar="GITGUARDIAN_EXIT_ZERO",
    help="Always return a 0 (non-error) status code, even if issues are found."
    "The env var GITGUARDIAN_EXIT_ZERO can also be used to set this option.",
)
@click.option(
    "--all-policies",
    is_flag=True,
    default=None,
    help="Present fails of all policies (Filenames, FileExtensions, Secret Detection)."
    "By default, only Secret Detection is shown.",
)
@click.option(
    "--verbose", "-v", is_flag=True, default=None, help="Verbose display mode.",
)
@click.pass_context
def scan(
    ctx: click.Context,
    mode: str,
    show_secrets: bool,
    exit_zero: bool,
    all_policies: bool,
    verbose: bool,
) -> int:
    """ Command to scan various contents. """
    api_key = os.getenv("GITGUARDIAN_API_KEY")
    base_uri = os.getenv("GITGUARDIAN_API_URL", ctx.obj["config"].api_url)
    if not api_key:
        raise click.ClickException("GitGuardian API Key is needed.")

    ctx.obj["client"] = GGClient(
        api_key=api_key, base_uri=base_uri, user_agent="ggshield", timeout=60
    )
    return_code = 0

    ctx.obj["filter_set"] = path_filter_set(
        Path(os.getcwd()), ctx.obj["config"].paths_ignore
    )
    if show_secrets is not None:
        ctx.obj["config"].show_secrets = show_secrets

    if all_policies is not None:
        ctx.obj["config"].all_policies = all_policies

    if verbose is not None:
        ctx.obj["config"].verbose = verbose

    if exit_zero is not None:
        ctx.obj["config"].exit_zero = exit_zero

    if ctx.invoked_subcommand is None:
        if mode:
            click.echo(
                "--mode has been deprecated and will be removed "
                "after ggshield version 1.2. prefer to use subcommands."
            )
            if mode == "pre-commit":
                return ctx.invoke(precommit_cmd)
            elif mode == "ci":
                return ctx.invoke(ci_cmd)
            else:
                click.echo(ctx.get_help())
        else:
            click.echo(ctx.get_help())
    return return_code


@scan.resultcallback()
@click.pass_context
def exit_code(ctx: click.Context, exit_code: int, **kwargs):
    """
    exit_code guarantees that the return value of a scan is 0
    when exit_zero is enabled
    """

    if ctx.obj["config"].exit_zero:
        sys.exit(0)

    sys.exit(exit_code)


@click.group(
    context_settings=CONTEXT_SETTINGS, commands={"scan": scan, "install": install}
)
@click.option(
    "-c",
    "--config-path",
    type=click.Path(exists=True, resolve_path=True, file_okay=True, dir_okay=False),
    help="Set a custom config file. Ignores local and global config files.",
)
@click.option(
    "--verbose", "-v", is_flag=True, default=None, help="Verbose display mode.",
)
@click.pass_context
def cli(ctx: click.Context, config_path: str, verbose: bool):
    ctx.ensure_object(dict)
    if config_path:
        Config.CONFIG_LOCAL = [config_path]
        Config.CONFIG_GLOBAL = []

    ctx.obj["config"] = Config()

    if verbose is not None:
        ctx.obj["config"].verbose = verbose


if __name__ == "__main__":
    cli()
