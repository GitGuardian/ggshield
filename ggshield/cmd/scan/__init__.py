import os
from typing import List, Optional, Type

import click

from ggshield.cmd.scan.archive import archive_cmd
from ggshield.cmd.scan.ci import ci_cmd
from ggshield.cmd.scan.docker import docker_name_cmd
from ggshield.cmd.scan.dockerarchive import docker_archive_cmd
from ggshield.cmd.scan.path import path_cmd
from ggshield.cmd.scan.precommit import precommit_cmd
from ggshield.cmd.scan.prepush import prepush_cmd
from ggshield.cmd.scan.prereceive import prereceive_cmd
from ggshield.cmd.scan.pypi import pypi_cmd
from ggshield.cmd.scan.range import range_cmd
from ggshield.cmd.scan.repo import repo_cmd
from ggshield.core.client import retrieve_client
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
    help="Ignore excluded patterns by default. [default: False]",
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
    """Command to scan various contents."""
    ctx.obj["client"] = retrieve_client(ctx.obj["config"])
    return_code = 0

    paths_ignore = ctx.obj["config"].paths_ignore
    if exclude is not None:
        paths_ignore.update(exclude)

    if not ignore_default_excludes and not ctx.obj["config"].ignore_default_excludes:
        paths_ignore.update(IGNORED_DEFAULT_WILDCARDS)

    ctx.obj["exclusion_regexes"] = init_exclusion_regexes(paths_ignore)
    config: Config = ctx.obj["config"]

    if show_secrets is not None:
        config.show_secrets = show_secrets

    if all_policies is not None:
        config.all_policies = all_policies

    if verbose is not None:
        config.verbose = verbose

    if exit_zero is not None:
        config.exit_zero = exit_zero

    if banlist_detector:
        config.banlisted_detectors.update(banlist_detector)

    max_commits = get_max_commits_for_hook()
    if max_commits:
        config.max_commits_for_hook = max_commits

    output_handler_cls: Type[OutputHandler] = TextOutputHandler
    if json_output:
        output_handler_cls = JSONOutputHandler

    ctx.obj["output_handler"] = output_handler_cls(
        show_secrets=config.show_secrets, verbose=config.verbose, output=output
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
