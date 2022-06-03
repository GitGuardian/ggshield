from typing import List, Optional

import click

from ggshield.cmd.secret.scan import (
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
from ggshield.core.utils import json_output_option_decorator


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
def deprecated_scan_group(
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
    """
    Deprecated: use `ggshield secret scan (...)` instead.
    """
    display_warning(
        "Warning: Using `ggshield scan (...)` is deprecated. Use `ggshield secret scan (...)` instead.",
    )
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
