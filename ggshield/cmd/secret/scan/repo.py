import re
import tempfile
from pathlib import Path
from typing import Any

import click
from click import UsageError

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.client import create_client_from_config
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.utils.git_shell import git
from ggshield.verticals.secret.repo import scan_repo_path


# Source: https://github.com/jonschlinkert/is-git-url MIT LICENSE
# TODO: it should be possible to scan a repo URL which does not end with ".git"
REGEX_GIT_URL = re.compile(
    r"(?:git|ssh|https?|git@[-\w.]+):(//)?(.*?)(\.git)(/?|#[-\d\w._]+?)$"
)


@click.command()
@click.argument("repository", nargs=1, type=click.STRING, required=True)
@add_secret_scan_common_options()
@click.pass_context
def repo_cmd(
    ctx: click.Context, repository: str, **kwargs: Any
) -> int:  # pragma: no cover
    """
    Scan a REPOSITORY's commits at the given URL or path.

    REPOSITORY is the clone URL or the path of the repository to scan.
    """
    ctx_obj = ContextObj.get(ctx)
    config = ctx_obj.config
    cache = ctx_obj.cache
    ctx_obj.client = create_client_from_config(config)

    scan_context = ScanContext(
        scan_mode=ScanMode.REPO,
        command_path=ctx.command_path,
    )

    path = Path(repository)
    if path.is_dir():
        scan_context.target_path = path
        return scan_repo_path(
            client=ctx_obj.client,
            cache=cache,
            output_handler=create_output_handler(ctx),
            exclusion_regexes=ctx_obj.exclusion_regexes,
            config=config,
            scan_context=scan_context,
            repo_path=path,
        )

    if REGEX_GIT_URL.match(repository):
        with tempfile.TemporaryDirectory() as tmpdirname:
            git(["clone", "--mirror", repository, tmpdirname])
            scan_context.target_path = Path(tmpdirname)
            return scan_repo_path(
                client=ctx_obj.client,
                cache=cache,
                output_handler=create_output_handler(ctx),
                exclusion_regexes=ctx_obj.exclusion_regexes,
                config=config,
                scan_context=scan_context,
                repo_path=Path(tmpdirname),
            )

    if any(host in repository for host in ("gitlab.com", "github.com")):
        raise UsageError(
            f"{repository} doesn't seem to be a valid git URL.\n"
            f"Did you mean {repository}.git?"
        )
    raise UsageError(f"{repository} is neither a valid path nor a git URL")
