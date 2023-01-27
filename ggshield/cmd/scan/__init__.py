from typing import Any, Optional

import click

from ggshield.cmd.secret.scan import (
    add_secret_scan_common_options,
    archive_cmd,
    ci_cmd,
    docker_archive_cmd,
    docker_name_cmd,
    path_cmd,
    precommit_cmd,
    prepush_cmd,
    prereceive_cmd,
    pypi_cmd,
    range_cmd,
    repo_cmd,
    scan_group_impl,
)
from ggshield.core.text_utils import display_error


@click.group(
    hidden=True,
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
def deprecated_scan_group(
    ctx: click.Context,
    all_policies: Optional[bool] = None,
    ignore_default_excludes: bool = False,
    **kwargs: Any,
) -> int:
    """
    Deprecated: use `ggshield secret scan (...)` instead.
    """
    # We use `display_error` to print this warning message in red color
    display_error(
        "Warning: The `ggshield scan (...)` commands are deprecated and will be removed in version 1.15.0. "
        "Use `ggshield secret scan (...)` instead."
    )
    return scan_group_impl(ctx)
