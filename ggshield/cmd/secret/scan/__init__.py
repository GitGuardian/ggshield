import os
from typing import List, Optional, Type

import click

from ggshield.cmd.secret.scan.archive import archive_cmd
from ggshield.cmd.secret.scan.ci import ci_cmd
from ggshield.cmd.secret.scan.docker import docker_name_cmd
from ggshield.cmd.secret.scan.dockerarchive import docker_archive_cmd
from ggshield.cmd.secret.scan.path import path_cmd
from ggshield.cmd.secret.scan.precommit import precommit_cmd
from ggshield.cmd.secret.scan.prepush import prepush_cmd
from ggshield.cmd.secret.scan.prereceive import prereceive_cmd
from ggshield.cmd.secret.scan.pypi import pypi_cmd
from ggshield.cmd.secret.scan.range import range_cmd
from ggshield.cmd.secret.scan.repo import repo_cmd
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.filter import init_exclusion_regexes
from ggshield.core.text_utils import display_error
from ggshield.core.utils import IGNORED_DEFAULT_WILDCARDS, json_output_option_decorator
from ggshield.output import JSONOutputHandler, OutputHandler, TextOutputHandler


@click.group(
    commands={
        "commit-range": range_cmd,
        "pre-commit": precommit_cmd,
        "pre-push": prepush_cmd,
        "pre-receive": prereceive_cmd,
        "ci": ci_cmd,
        "path": path_cmd,
        "repo": repo_cmd,
        "docker": docker_name_cmd,
        "docker-archive": docker_archive_cmd,
        "pypi": pypi_cmd,
        "archive": archive_cmd,
    },
)
@json_output_option_decorator
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
    hidden=True,
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
@click.option(
    "--banlist-detector",
    "-b",
    default=None,
    help="Exclude results from a detector.",
    multiple=True,
)
@click.option(
    "--exclude",
    default=None,
    type=click.Path(),
    help="Do not scan the specified path.",
    multiple=True,
)
@click.option(
    "--ignore-default-excludes",
    default=False,
    is_flag=True,
    hidden=True,
)
@click.pass_context
def scan_group(
    ctx: click.Context,
    show_secrets: bool,
    exit_zero: bool,
    all_policies: bool,
    verbose: bool,
    json_output: bool,
    output: Optional[str],
    banlist_detector: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
    ignore_default_excludes: bool = False,
) -> int:
    """Commands to scan various contents."""
    return scan_group_impl(
        ctx,
        show_secrets,
        exit_zero,
        verbose,
        json_output,
        output,
        banlist_detector,
        exclude,
    )


def scan_group_impl(
    ctx: click.Context,
    show_secrets: bool,
    exit_zero: bool,
    verbose: bool,
    json_output: bool,
    output: Optional[str],
    banlist_detector: Optional[List[str]] = None,
    exclude: Optional[List[str]] = None,
) -> int:
    """Implementation for scan_group(). Must be a separate function so that its code can
    be reused from the deprecated `cmd.scan` package."""
    ctx.obj["client"] = create_client_from_config(ctx.obj["config"])
    return_code = 0

    ignored_paths = ctx.obj["config"].secret.ignored_paths
    if exclude is not None:
        ignored_paths.update(exclude)

    ignored_paths.update(IGNORED_DEFAULT_WILDCARDS)

    ctx.obj["exclusion_regexes"] = init_exclusion_regexes(ignored_paths)
    config: Config = ctx.obj["config"]

    if show_secrets is not None:
        config.secret.show_secrets = show_secrets

    if verbose is not None:
        config.verbose = verbose

    if exit_zero is not None:
        config.exit_zero = exit_zero

    if banlist_detector:
        config.secret.ignored_detectors.update(banlist_detector)

    max_commits = get_max_commits_for_hook()
    if max_commits:
        config.max_commits_for_hook = max_commits

    output_handler_cls: Type[OutputHandler] = TextOutputHandler
    if json_output:
        output_handler_cls = JSONOutputHandler

    ctx.obj["output_handler"] = output_handler_cls(
        show_secrets=config.secret.show_secrets, verbose=config.verbose, output=output
    )

    return return_code


def get_max_commits_for_hook() -> Optional[int]:
    """
    Get the maximum number of commits that should be processed for a hook.
    """
    try:
        max_commits = os.getenv("GITGUARDIAN_MAX_COMMITS_FOR_HOOK", None)
        if max_commits is not None:
            return int(max_commits)
    except BaseException as e:
        display_error(f"Unable to parse GITGUARDIAN_MAX_COMMITS_FOR_HOOK: {str(e)}")
        return None

    return None
