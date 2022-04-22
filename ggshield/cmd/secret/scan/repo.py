import os
import tempfile

import click
from pygitguardian import GGClient

from ggshield.core.cache import Cache
from ggshield.core.config import Config
from ggshield.core.git_shell import GIT_PATH, shell
from ggshield.core.utils import REGEX_GIT_URL
from ggshield.scan.repo import scan_repo_path


@click.command()
@click.argument("repository", nargs=1, type=click.STRING, required=True)
@click.pass_context
def repo_cmd(ctx: click.Context, repository: str) -> int:  # pragma: no cover
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
    if os.path.isdir(repository):
        return scan_repo_path(
            client=client,
            cache=cache,
            output_handler=ctx.obj["output_handler"],
            config=config,
            repo_path=repository,
            scan_id=repository,
        )

    if REGEX_GIT_URL.match(repository):
        with tempfile.TemporaryDirectory() as tmpdirname:
            shell([GIT_PATH, "clone", repository, tmpdirname])
            return scan_repo_path(
                client=client,
                cache=cache,
                output_handler=ctx.obj["output_handler"],
                config=config,
                repo_path=tmpdirname,
                scan_id=repository,
            )

    if any(host in repository for host in ("gitlab.com", "github.com")):
        raise click.ClickException(
            f"{repository} doesn't seem to be a valid git URL.\n"
            f"Did you mean {repository}.git?"
        )
    raise click.ClickException(f"{repository} is neither a valid path nor a git URL")
