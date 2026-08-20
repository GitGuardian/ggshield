import logging
import os
import sys
from typing import Any, Optional

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.cmd.utils.lazy_group import LazyGroup
from ggshield.core import ui
from ggshield.core.errors import ExitCode


logger = logging.getLogger(__name__)


@click.group(
    cls=LazyGroup,
    lazy_commands={
        "ai-hook": "ggshield.cmd.secret.scan.ai_hook:ai_hook_cmd",
        "commit-range": "ggshield.cmd.secret.scan.range:range_cmd",
        "changes": "ggshield.cmd.secret.scan.changes:changes_cmd",
        "pre-commit": "ggshield.cmd.secret.scan.precommit:precommit_cmd",
        "pre-push": "ggshield.cmd.secret.scan.prepush:prepush_cmd",
        "pre-receive": "ggshield.cmd.secret.scan.prereceive:prereceive_cmd",
        "ci": "ggshield.cmd.secret.scan.ci:ci_cmd",
        "path": "ggshield.cmd.secret.scan.path:path_cmd",
        "repo": "ggshield.cmd.secret.scan.repo:repo_cmd",
        "docker": "ggshield.cmd.secret.scan.docker:docker_name_cmd",
        "docker-archive": "ggshield.cmd.secret.scan.dockerarchive:docker_archive_cmd",
        "pypi": "ggshield.cmd.secret.scan.pypi:pypi_cmd",
        "archive": "ggshield.cmd.secret.scan.archive:archive_cmd",
        "docset": "ggshield.cmd.secret.scan.docset:docset_cmd",
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


# Lives here rather than in __main__ so that registering it does not require
# importing the scan group on every ggshield invocation.
@scan_group.result_callback()
@click.pass_context
def exit_code(ctx: click.Context, exit_code: int, **kwargs: Any) -> int:
    """
    exit_code guarantees that the return value of a scan is 0
    when exit_zero is enabled
    """
    ctx_obj = ContextObj.get(ctx)
    if (
        exit_code == ExitCode.SCAN_FOUND_PROBLEMS
        and ctx_obj.config.user_config.exit_zero
    ):
        logger.debug("scan exit_code forced to 0")
        sys.exit(ExitCode.SUCCESS)

    logger.debug("scan exit_code=%d", exit_code)
    return exit_code


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
