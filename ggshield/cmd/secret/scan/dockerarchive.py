from pathlib import Path
from typing import Any

import click

from ggshield.cmd.secret.scan.secret_scan_common_options import (
    add_secret_scan_common_options,
    create_output_handler,
)
from ggshield.cmd.utils.common_decorators import exception_wrapper
from ggshield.cmd.utils.context_obj import ContextObj
from ggshield.core.client import create_client_from_config
from ggshield.core.scan import ScanContext, ScanMode
from ggshield.utils.click import RealPath
from ggshield.verticals.secret.docker import docker_scan_archive


@click.command(hidden=True)
@click.argument(
    "archive", nargs=1, type=RealPath(exists=True, resolve_path=True), required=True
)
@add_secret_scan_common_options()
@click.pass_context
@exception_wrapper
def docker_archive_cmd(
    ctx: click.Context,
    archive: Path,
    **kwargs: Any,
) -> int:  # pragma: no cover
    """
    Scan a docker archive <ARCHIVE> without attempting to save or pull the image.

    Hidden command `ggshield secret scan docker-archive`
    """
    ctx_obj = ContextObj.get(ctx)
    ctx_obj.client = create_client_from_config(ctx_obj.config)
    config = ctx_obj.config
    output_handler = create_output_handler(ctx)

    scan_context = ScanContext(
        scan_mode=ScanMode.DOCKER,
        command_path=ctx.command_path,
    )

    scan = docker_scan_archive(
        archive_path=archive,
        client=ctx_obj.client,
        cache=ctx_obj.cache,
        secret_config=config.user_config.secret,
        scan_context=scan_context,
        exclusion_regexes=ctx_obj.exclusion_regexes,
    )

    return output_handler.process_scan(scan)
