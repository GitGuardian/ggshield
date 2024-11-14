import os
from typing import Any, Optional

import click

from ggshield.cmd.secret.scan.archive import archive_cmd
from ggshield.cmd.secret.scan.changes import changes_cmd
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
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core import ui


@click.group(
    commands={
        "commit-range": range_cmd,
        "changes": changes_cmd,
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
    all_policies: Optional[bool] = None,
    ignore_default_excludes: bool = False,
    **kwargs: Any,
) -> int:
    """Commands to scan various contents."""
    return scan_group_impl(ctx)


def scan_group_impl(ctx: click.Context) -> int:
    """Implementation for scan_group(). Must be a separate function so that its code can
    be reused from the deprecated `cmd.scan` package."""
    ctx_obj = ContextObj.get(ctx)
    return_code = 0

    config = ctx_obj.config

    max_commits = get_max_commits_for_hook()
    if max_commits:
        config.user_config.max_commits_for_hook = max_commits

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
        ui.display_error(f"Unable to parse GITGUARDIAN_MAX_COMMITS_FOR_HOOK: {str(e)}")
        return None

    return None
