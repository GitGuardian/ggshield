import subprocess
import tempfile
import traceback
from pathlib import Path
from typing import Any, Dict, Iterable, List

import click
from pygitguardian.client import GGClient

from ggshield.config import Cache
from ggshield.output import OutputHandler
from ggshield.scan import ScanCollection, get_files_from_docker_archive

from .utils import SupportedScanMode


# bailout if docker command takes longer than 6 minutes
DOCKER_COMMAND_TIMEOUT = 360


class DockerArchiveCreationError(Exception):
    pass


def docker_pull_image(image_name: str) -> None:
    """
    Pull docker image and raise exception on timeout or failed to find image
    """
    command = ["docker", "pull", image_name]
    try:
        subprocess.run(
            command,
            check=True,
            timeout=DOCKER_COMMAND_TIMEOUT,
        )
    except subprocess.CalledProcessError:
        raise click.ClickException(f'Image "{image_name}" not found')
    except subprocess.TimeoutExpired:
        raise click.ClickException('Command "{}" timed out'.format(" ".join(command)))


def docker_save_to_tmp(image_name: str, temporary_path: str) -> Path:
    """
    Do a `docker save <image_name> -o <temporary_path>` and return the
    `temporary_path`.
    """
    temp_archive_filename = Path(temporary_path) / (
        image_name.replace("/", "--") + ".tar"
    )
    command = ["docker", "save", image_name, "-o", str(temp_archive_filename)]

    try:
        subprocess.run(
            command,
            check=True,
            stderr=subprocess.PIPE,
            timeout=DOCKER_COMMAND_TIMEOUT,
        )
    except subprocess.CalledProcessError as exc:
        err_string = str(exc.stderr)
        if "No such image" in err_string or "reference does not exist" in err_string:
            docker_pull_image(image_name)

            return docker_save_to_tmp(image_name, temporary_path)
        raise click.ClickException("Unable to save docker archive")
    except subprocess.TimeoutExpired:
        raise click.ClickException('Command "{}" timed out'.format(" ".join(command)))

    return temp_archive_filename


def docker_scan_archive(
    archive: str,
    client: GGClient,
    cache: Cache,
    verbose: bool,
    matches_ignore: Iterable[str],
    all_policies: bool,
    scan_id: str,
) -> ScanCollection:
    files = get_files_from_docker_archive(archive)
    with click.progressbar(length=len(files.files), label="Scanning") as progressbar:

        def update_progress(chunk: List[Dict[str, Any]]) -> None:
            progressbar.update(len(chunk))

        results = files.scan(
            client=client,
            cache=cache,
            matches_ignore=matches_ignore,
            all_policies=all_policies,
            verbose=verbose,
            mode_header=SupportedScanMode.DOCKER.value,
            on_file_chunk_scanned=update_progress,
        )

    return ScanCollection(id=scan_id, type="scan_docker_archive", results=results)


@click.command()
@click.argument("name", nargs=1, type=click.STRING, required=True)
@click.pass_context
def docker_name_cmd(ctx: click.Context, name: str) -> int:
    """
    scan a docker image <NAME>.

    ggshield will try to pull the image if it's not available locally.
    """

    with tempfile.TemporaryDirectory(suffix="ggshield") as temporary_dir:
        config = ctx.obj["config"]
        output_handler: OutputHandler = ctx.obj["output_handler"]

        try:
            archive = str(docker_save_to_tmp(name, temporary_dir))

            scan = docker_scan_archive(
                archive=archive,
                client=ctx.obj["client"],
                cache=ctx.obj["cache"],
                verbose=config.verbose,
                matches_ignore=config.matches_ignore,
                all_policies=config.all_policies,
                scan_id=name,
            )

            return output_handler.process_scan(scan)[1]
        except click.exceptions.Abort:
            return 0
        except Exception as error:
            if config.verbose:
                traceback.print_exc()

            raise click.ClickException(str(error))


@click.command(hidden=True)
@click.argument(
    "archive", nargs=1, type=click.Path(exists=True, resolve_path=True), required=True
)
@click.pass_context
def docker_archive_cmd(
    ctx: click.Context,
    archive: str,
) -> int:  # pragma: no cover
    """
    scan a docker archive <ARCHIVE> without attempting to save or pull the image.

    Hidden command `ggshield scan docker-archive`
    """
    config = ctx.obj["config"]
    output_handler: OutputHandler = ctx.obj["output_handler"]

    try:
        scan = docker_scan_archive(
            archive=archive,
            client=ctx.obj["client"],
            cache=ctx.obj["cache"],
            verbose=config.verbose,
            matches_ignore=config.matches_ignore,
            all_policies=config.all_policies,
            scan_id=archive,
        )

        return output_handler.process_scan(scan)[1]
    except click.exceptions.Abort:
        return 0
    except Exception as error:
        if config.verbose:
            traceback.print_exc()

        raise click.ClickException(str(error))
