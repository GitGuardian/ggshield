#!/usr/bin/python3
import os
import sys
from pathlib import Path
from typing import Any, NoReturn, Optional, Type, cast

import click

from ggshield.output import JSONHandler, OutputHandler, TextHandler

from .ci import ci_cmd
from .config import CONTEXT_SETTINGS, Cache, Config, load_dot_env
from .dev_scan import path_cmd, range_cmd, repo_cmd
from .docker import docker_archive_cmd, docker_name_cmd
from .filter import path_filter_set
from .hook_cmd import precommit_cmd, prepush_cmd
from .ignore import ignore
from .install import install
from .quota import quota
from .status import status
from .utils import json_output_option_decorator, retrieve_client


@click.group(
    commands={
        "commit-range": range_cmd,
        "pre-commit": precommit_cmd,
        "pre-push": prepush_cmd,
        "ci": ci_cmd,
        "path": path_cmd,
        "repo": repo_cmd,
        "docker": docker_name_cmd,
        "docker-archive": docker_archive_cmd,
    },
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
    help="Always return a 0 (non-error) status code, even if incidents are found."
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
    "--verbose", "-v", is_flag=True, default=None, help="Verbose display mode."
)
@click.option(
    "--output",
    "-o",
    type=click.Path(exists=False, resolve_path=True),
    default=None,
    help="Route ggshield output to file.",
)
@click.pass_context
def scan(
    ctx: click.Context,
    show_secrets: bool,
    exit_zero: bool,
    all_policies: bool,
    verbose: bool,
    json_output: bool,
    output: Optional[str],
) -> int:
    """Command to scan various contents."""
    ctx.obj["client"] = retrieve_client(ctx)
    return_code = 0

    ctx.obj["filter_set"] = path_filter_set(
        Path(os.getcwd()), ctx.obj["config"].paths_ignore
    )
    config: Config = ctx.obj["config"]

    if show_secrets is not None:
        config.show_secrets = show_secrets

    if all_policies is not None:
        config.all_policies = all_policies

    if verbose is not None:
        config.verbose = verbose

    if exit_zero is not None:
        config.exit_zero = exit_zero

    output_handler_cls: Type[OutputHandler] = TextHandler
    if json_output:
        output_handler_cls = JSONHandler

    ctx.obj["output_handler"] = output_handler_cls(
        show_secrets=config.show_secrets, verbose=config.verbose, output=output
    )

    return return_code


scan = cast(click.Group, json_output_option_decorator(scan))


@scan.resultcallback()
@click.pass_context
def exit_code(ctx: click.Context, exit_code: int, **kwargs: Any) -> None:
    """
    exit_code guarantees that the return value of a scan is 0
    when exit_zero is enabled
    """

    if ctx.obj["config"].exit_zero:
        sys.exit(0)

    sys.exit(exit_code)


@click.group(
    context_settings=CONTEXT_SETTINGS,
    commands={
        "scan": scan,
        "install": install,
        "ignore": ignore,
        "quota": quota,
        "api-status": status,
    },
)
@click.option(
    "-c",
    "--config-path",
    type=click.Path(exists=True, resolve_path=True, file_okay=True, dir_okay=False),
    help="Set a custom config file. Ignores local and global config files.",
)
@click.option(
    "--verbose", "-v", is_flag=True, default=None, help="Verbose display mode."
)
@click.option(
    "--allow-self-signed",
    is_flag=True,
    default=None,
    help="Ignore ssl verification.",
)
@click.version_option()
@click.pass_context
def cli(
    ctx: click.Context, config_path: str, verbose: bool, allow_self_signed: bool
) -> None:
    load_dot_env()
    ctx.ensure_object(dict)
    if config_path:
        Config.CONFIG_LOCAL = [config_path]
        Config.CONFIG_GLOBAL = []

    ctx.obj["config"] = Config()
    ctx.obj["cache"] = Cache()

    if verbose is not None:
        ctx.obj["config"].verbose = verbose

    if allow_self_signed is not None:
        ctx.obj["config"].allow_self_signed = allow_self_signed


def cli_wrapper() -> NoReturn:
    standalone_mode = not (
        os.getenv("GITGUARDIAN_CRASH_LOG", "False").lower() == "true"
    )
    return_code = cli.main(standalone_mode=standalone_mode)
    exit(return_code)


if __name__ == "__main__":
    cli_wrapper()
