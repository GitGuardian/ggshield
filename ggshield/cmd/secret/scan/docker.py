import tempfile
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
from ggshield.secret.docker import docker_save_to_tmp, docker_scan_archive


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
def docker_name_cmd(
    ctx: click.Context, name: str, docker_timeout: int, **kwargs: Any
) -> int:
    """
    scan a docker image <NAME>.

    ggshield will try to pull the image if it's not available locally.
    """

    with tempfile.TemporaryDirectory(suffix="ggshield") as temporary_dir:
        config: Config = ctx.obj["config"]
        output_handler = create_output_handler(ctx)

        try:
            archive = Path(temporary_dir) / "archive.tar"
            docker_save_to_tmp(name, archive, docker_timeout)

            scan_context = ScanContext(
                scan_mode=ScanMode.DOCKER,
                command_path=ctx.command_path,
            )

            scan = docker_scan_archive(
                archive_path=archive,
                client=ctx.obj["client"],
                cache=ctx.obj["cache"],
                scan_context=scan_context,
                matches_ignore=config.user_config.secret.ignored_matches,
                ignored_detectors=config.user_config.secret.ignored_detectors,
            )

            return output_handler.process_scan(scan)
        except Exception as error:
            return handle_exception(error, config.user_config.verbose)
