import json
import os.path
import tarfile
from itertools import chain
from typing import Any, Dict, Iterable, Tuple

from ggshield.config import MAX_FILE_SIZE

from .scannable import File, Files


class InvalidDockerArchiveException(Exception):
    pass


def get_files_from_docker_archive(archive_path: str) -> Files:
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
        File(
            config_file_content,
            filename=os.path.join(archive.name, config_file_path),  # type: ignore
            filesize=config_file_info.size,
        ),
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
            "created_by": info["created_by"],
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
    return "COPY" in cmd or "ADD" in cmd


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
    Extracts File objects to be scanner for given layer.
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

        file = layer_archive.extractfile(file_info)
        if file is None:
            continue

        file_content_raw = file.read()
        if len(file_content_raw) > MAX_FILE_SIZE * 0.95:
            continue

        file_content = file_content_raw.decode(errors="replace").replace("\0", "�")
        yield File(
            document=file_content,
            filename=os.path.join(archive.name, layer_filename, file_info.name),  # type: ignore # noqa
            filesize=file_info.size,
        )
