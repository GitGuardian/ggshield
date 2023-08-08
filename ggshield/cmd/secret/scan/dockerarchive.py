from pathlib import Path
from typing import Any

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.core.config import Config
from ggshield.core.errors import handle_exception
from ggshield.scan import ScanContext, ScanMode
from ggshield.secret.docker import docker_scan_archive


@click.command(hidden=True)
@click.argument(
    "archive", nargs=1, type=click.Path(exists=True, resolve_path=True), required=True
)
@add_secret_scan_common_options()
@click.pass_context
def docker_archive_cmd(
    ctx: click.Context,
    archive: Path,
    **kwargs: Any,
) -> int:  # pragma: no cover
    """
    scan a docker archive <ARCHIVE> without attempting to save or pull the image.

    Hidden command `ggshield secret scan docker-archive`
    """
    config: Config = ctx.obj["config"]
    output_handler = create_output_handler(ctx)

    scan_context = ScanContext(
        scan_mode=ScanMode.DOCKER,
        command_path=ctx.command_path,
    )

    try:
        scan = docker_scan_archive(
            archive_path=archive,
            client=ctx.obj["client"],
            cache=ctx.obj["cache"],
            matches_ignore=config.user_config.secret.ignored_matches,
            scan_context=scan_context,
            ignored_detectors=config.user_config.secret.ignored_detectors,
        )

        return output_handler.process_scan(scan)
    except Exception as error:
        return handle_exception(error, config.user_config.verbose)
