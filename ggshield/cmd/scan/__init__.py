from typing import Any, List, Optional

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
from ggshield.core.text_utils import display_warning


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
def deprecated_scan_group(
    ctx: click.Context,
    output: Optional[str],
    banlist_detector: Optional[List[str]] = None,
    all_policies: Optional[bool] = None,
    ignore_default_excludes: bool = False,
    **kwargs: Any,
) -> int:
    """
    Deprecated: use `ggshield secret scan (...)` instead.
    """
    display_warning(
        "Warning: Using `ggshield scan (...)` is deprecated. Use `ggshield secret scan (...)` instead.",
    )
    return scan_group_impl(
        ctx,
        output,
        banlist_detector,
    )
