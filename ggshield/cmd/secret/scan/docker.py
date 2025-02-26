import tempfile
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
from ggshield.verticals.secret.docker import docker_save_to_tmp, docker_scan_archive


# bailout if docker command takes longer than 6 minutes
DOCKER_COMMAND_TIMEOUT = 360


@click.command()
@click.option(
    "--docker-timeout",
    type=click.INT,
    default=DOCKER_COMMAND_TIMEOUT,
    help="Timeout for Docker commands.",
    metavar="SECONDS",
    show_default=True,
)
@click.argument("name", nargs=1, type=click.STRING, required=True)
@add_secret_scan_common_options()
@click.pass_context
@exception_wrapper
def docker_name_cmd(
    ctx: click.Context, name: str, docker_timeout: int, **kwargs: Any
) -> int:
    """
    Scan a Docker image after exporting its filesystem and manifest with the `docker save` command.

    ggshield tries to pull the image if it's not available locally.
    """

    with tempfile.TemporaryDirectory(suffix="ggshield") as temporary_dir:
        ctx_obj = ContextObj.get(ctx)
        ctx_obj.client = create_client_from_config(ctx_obj.config)
        config = ctx_obj.config
        output_handler = create_output_handler(ctx)

        archive = Path(temporary_dir) / "archive.tar"
        docker_save_to_tmp(name, archive, docker_timeout)

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
