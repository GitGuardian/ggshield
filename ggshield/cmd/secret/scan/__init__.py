import os
from typing import Any, List, Optional

import click

from ggshield.cmd.secret.scan.archive import archive_cmd
from ggshield.cmd.secret.scan.ci import ci_cmd
from ggshield.cmd.secret.scan.docker import docker_name_cmd
from ggshield.cmd.secret.scan.dockerarchive import docker_archive_cmd
from ggshield.cmd.secret.scan.docset import docset_cmd
from ggshield.cmd.secret.scan.path import path_cmd
from ggshield.cmd.secret.scan.precommit import precommit_cmd
from ggshield.cmd.secret.scan.prepush import prepush_cmd
from ggshield.cmd.secret.scan.prereceive import prereceive_cmd
from ggshield.cmd.secret.scan.pypi import pypi_cmd
from ggshield.cmd.secret.scan.range import range_cmd
from ggshield.cmd.secret.scan.repo import repo_cmd
from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
)
from ggshield.core.client import create_client_from_config
from ggshield.core.config import Config
from ggshield.core.text_utils import display_error
from ggshield.core.utils import json_output_option_decorator
from ggshield.output import JSONOutputHandler, TextOutputHandler


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
        "docset": docset_cmd,
    },
)
@json_output_option_decorator
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
# Deprecated options
@click.option(
    "--all-policies",
    is_flag=True,
    default=None,
    hidden=True,
)
@click.option(
    "--ignore-default-excludes",
    default=False,
    is_flag=True,
    hidden=True,
)
@add_secret_scan_common_options()
@click.pass_context
def scan_group(
    ctx: click.Context,
    json_output: bool,
    output: Optional[str],
    banlist_detector: Optional[List[str]] = None,
    all_policies: Optional[bool] = None,
    ignore_default_excludes: bool = False,
    **kwargs: Any,
) -> int:
    """Commands to scan various contents."""
    return scan_group_impl(
        ctx,
        json_output,
        output,
        banlist_detector,
    )


def scan_group_impl(
    ctx: click.Context,
    json_output: bool,
    output: Optional[str],
    banlist_detector: Optional[List[str]] = None,
) -> int:
    """Implementation for scan_group(). Must be a separate function so that its code can
    be reused from the deprecated `cmd.scan` package."""
    ctx.obj["client"] = create_client_from_config(ctx.obj["config"])
    return_code = 0

    config: Config = ctx.obj["config"]

    if banlist_detector:
        config.secret.ignored_detectors.update(banlist_detector)

    max_commits = get_max_commits_for_hook()
    if max_commits:
        config.max_commits_for_hook = max_commits

    if json_output:
        ctx.obj["output_handler_cls"] = JSONOutputHandler
    else:
        ctx.obj["output_handler_cls"] = TextOutputHandler
    ctx.obj["output"] = output

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
