import json
import os.path
import re
import subprocess
import sys
import tarfile
from itertools import chain
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import click
from pygitguardian import GGClient

from ggshield.core.cache import Cache
from ggshield.core.constants import MAX_FILE_SIZE
from ggshield.core.utils import SupportedScanMode
from ggshield.scan import ScanCollection
from ggshield.scan.scannable import File, Files


DEFAULT_FS_BANLIST = {
    "/usr/",
    "/lib/",
    "/share/",
    "/bin/",
    "/sbin/",
    "/node_modules/",
    "/include/",
    "/vendor/",
    "/texlive/",
    "/var/",
    "/fonts/",
    "/npm/",
    "/site-packages/",
    "/gems/",
}

DEFAULT_EXTENSION_BANLIST = {".md", ".html", ".css", ".lock", ".storyboard", ".xib"}

LAYER_TO_SCAN_PATTERN = re.compile(r"\b(copy|add)\b", re.IGNORECASE)


class InvalidDockerArchiveException(Exception):
    pass


def get_files_from_docker_archive(archive_path: Path) -> Files:
    """
    Extracts files to scan from a Docker image archive.
    Only the configuration and the layers generated with a `COPY` and `ADD`
    command are scanned.
    """
    with tarfile.open(archive_path) as archive:
        manifest, config, config_file_to_scan = _get_config(archive)

        layer_files_to_scan = _get_layers_files(
            archive, filter(_should_scan_layer, _get_layer_infos(manifest, config))
        )

        return Files(list(chain((config_file_to_scan,), layer_files_to_scan)))


def _get_config(archive: tarfile.TarFile) -> Tuple[Dict, Dict, File]:
    """
    Extracts Docker image archive manifest and configuration.
    Returns a tuple with:
    - the deserialized manifest,
    - the deserialized configuration,
    - the configuration File object to scan.
    """
    manifest_file = archive.extractfile("manifest.json")
    if manifest_file is None:
        raise InvalidDockerArchiveException("No manifest file found.")

    manifest = json.load(manifest_file)[0]

    config_file_path = manifest.get("Config")

    config_file_info = archive.getmember(config_file_path)
    if config_file_info is None:
        raise InvalidDockerArchiveException("No config file found.")

    config_file = archive.extractfile(config_file_info)
    if config_file is None:
        raise InvalidDockerArchiveException("Config file could not be extracted.")

    config_file_content = config_file.read().decode()

    return (
        manifest,
        json.loads(config_file_content),
        File(config_file_content, filename="Dockerfile or build-args"),
    )


def _get_layer_infos(
    manifest: Dict[str, Any], config: Dict[str, Any]
) -> Iterable[Dict[str, Dict]]:
    """
    Extracts the non-empty layers information with:
    - the filename,
    - the command used to generate the layer,
    - and the date and time of creation.
    """
    return (
        {
            "filename": filename,
            "created": info["created"],
            "created_by": info.get("created_by"),
        }
        for info, filename in zip(
            (layer for layer in config["history"] if not layer.get("empty_layer")),
            manifest["Layers"],
        )
    )


def _should_scan_layer(layer_info: Dict) -> bool:
    """
    Returns True if a layer should be scanned, False otherwise.
    Only COPY and ADD layers should be scanned.
    """
    cmd = layer_info["created_by"]
    return LAYER_TO_SCAN_PATTERN.search(cmd) is not None if cmd else True


def _get_layers_files(
    archive: tarfile.TarFile, layers_info: Iterable[Dict]
) -> Iterable[File]:
    """
    Extracts File objects to be scanned for given layers.
    """
    for layer_info in layers_info:
        yield from _get_layer_files(archive, layer_info)


def _get_layer_files(archive: tarfile.TarFile, layer_info: Dict) -> Iterable[File]:
    """
    Extracts File objects to be scanned for given layer.
    """
    layer_filename = layer_info["filename"]
    layer_archive = tarfile.TarFile(
        name=os.path.join(archive.name, layer_filename),  # type: ignore
        fileobj=archive.extractfile(layer_filename),
    )

    for file_info in layer_archive:
        if not file_info.isfile():
            continue

        if file_info.size > MAX_FILE_SIZE * 0.95:
            continue

        if any(dir in "/" + file_info.path for dir in DEFAULT_FS_BANLIST):
            continue

        if any(file_info.path.endswith(ext) for ext in DEFAULT_EXTENSION_BANLIST):
            continue

        file = layer_archive.extractfile(file_info)
        if file is None:
            continue

        file_content = file.read()
        if len(file_content) > MAX_FILE_SIZE * 0.95:
            continue

        # layer_filename is "<some_uuid>/layer.tar". We only keep "<some_uuid>"
        layer_name = os.path.dirname(layer_filename)

        # Do not use os.path.join() for the filename argument: we always want Unix path
        # separators here
        yield File.from_bytes(
            raw_document=file_content, filename=f"{layer_name}:/{file_info.name}"
        )


class DockerArchiveCreationError(Exception):
    pass


def docker_pull_image(image_name: str, timeout: int) -> None:
    """
    Pull docker image and raise exception on timeout or failed to find image

    Timeout after `timeout` seconds.
    """
    command = ["docker", "pull", image_name]
    try:
        subprocess.run(
            command,
            check=True,
            timeout=timeout,
        )
    except subprocess.CalledProcessError:
        raise click.ClickException(f'Image "{image_name}" not found')
    except subprocess.TimeoutExpired:
        raise click.ClickException('Command "{}" timed out'.format(" ".join(command)))


def docker_save_to_tmp(image_name: str, destination_path: Path, timeout: int) -> None:
    """
    Do a `docker save <image_name> -o <destination_path>`

    Limit docker commands to run at most `timeout` seconds.
    """
    command = ["docker", "save", image_name, "-o", str(destination_path)]

    try:
        click.echo("Saving docker image... ", nl=False)
        subprocess.run(
            command,
            check=True,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        click.echo("OK")
    except subprocess.CalledProcessError as exc:
        err_string = str(exc.stderr)
        if "No such image" in err_string or "reference does not exist" in err_string:
            click.echo("need to download image first")
            docker_pull_image(image_name, timeout)

            docker_save_to_tmp(image_name, destination_path, timeout)
        else:
            raise click.ClickException(
                f"Unable to save docker archive:\nError: {err_string}"
            )
    except subprocess.TimeoutExpired:
        raise click.ClickException('Command "{}" timed out'.format(" ".join(command)))


def docker_scan_archive(
    archive: Path,
    client: GGClient,
    cache: Cache,
    verbose: bool,
    matches_ignore: Iterable[str],
    all_policies: bool,
    scan_id: str,
    banlisted_detectors: Optional[Set[str]] = None,
) -> ScanCollection:
    files = get_files_from_docker_archive(archive)
    with click.progressbar(
        length=len(files.files), label="Scanning", file=sys.stderr
    ) as progressbar:

        def update_progress(chunk: List[Dict[str, Any]]) -> None:
            progressbar.update(len(chunk))

        results = files.scan(
            client=client,
            cache=cache,
            matches_ignore=matches_ignore,
            all_policies=all_policies,
            mode_header=SupportedScanMode.DOCKER.value,
            banlisted_detectors=banlisted_detectors,
            on_file_chunk_scanned=update_progress,
        )

    return ScanCollection(id=scan_id, type="scan_docker_archive", results=results)
