import os
import tempfile
from typing import Any

import click
from click import UsageError
from pygitguardian import GGClient

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.core.cache import Cache
from ggshield.core.config import Config
from ggshield.core.git_shell import git
from ggshield.core.utils import REGEX_GIT_URL
from ggshield.scan import ScanContext, ScanMode
from ggshield.secret.repo import scan_repo_path


@click.command()
@click.argument("repository", nargs=1, type=click.STRING, required=True)
@add_secret_scan_common_options()
@click.pass_context
def repo_cmd(
    ctx: click.Context, repository: str, **kwargs: Any
) -> int:  # pragma: no cover
    """
    scan a REPOSITORY's commits at a given URL or path.

    REPOSITORY is the clone URI or the path of the repository to scan.
    Examples:

    ggshield secret scan repo git@github.com:GitGuardian/ggshield.git

    ggshield secret scan repo /repositories/ggshield
    """
    config: Config = ctx.obj["config"]
    cache: Cache = ctx.obj["cache"]
    client: GGClient = ctx.obj["client"]

    scan_context = ScanContext(
        scan_mode=ScanMode.REPO,
        command_path=ctx.command_path,
    )

    if os.path.isdir(repository):
        return scan_repo_path(
            client=client,
            cache=cache,
            output_handler=create_output_handler(ctx),
            config=config,
            scan_context=scan_context,
            repo_path=repository,
        )

    if REGEX_GIT_URL.match(repository):
        with tempfile.TemporaryDirectory() as tmpdirname:
            git(["clone", repository, tmpdirname])
            return scan_repo_path(
                client=client,
                cache=cache,
                output_handler=create_output_handler(ctx),
                config=config,
                scan_context=scan_context,
                repo_path=tmpdirname,
            )

    if any(host in repository for host in ("gitlab.com", "github.com")):
        raise UsageError(
            f"{repository} doesn't seem to be a valid git URL.\n"
            f"Did you mean {repository}.git?"
        )
    raise UsageError(f"{repository} is neither a valid path nor a git URL")
