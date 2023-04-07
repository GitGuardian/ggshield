import json
import os.path
import re
import subprocess
import tarfile
from functools import partial
from itertools import chain
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Set, Tuple

from click import UsageError
from pygitguardian import GGClient

from ggshield.core.cache import Cache
from ggshield.core.errors import UnexpectedError
from ggshield.core.file_utils import is_path_binary
from ggshield.core.text_utils import create_progress_bar, display_info
from ggshield.core.types import IgnoredMatch
from ggshield.scan import (
    Files,
    ScanCollection,
    ScanContext,
    Scannable,
    SecretScanner,
    StringScannable,
)


FILEPATH_BANLIST = [
    r"^/?usr/(?!share/nginx)",
    r"^/?lib/",
    r"^/?share/",
    r"^/?bin/",
    r"^/?sbin/",
    r"^/?node_modules/",
    r"^/?include/",
    r"^/?vendor/",
    r"^/?texlive/",
    r"^/?var/",
    r"^/?fonts/",
    r"^/?npm/",
    r"^/?site-packages/",
]
FILEPATH_BANLIST_PATTERNS = {
    re.compile(banned_filepath) for banned_filepath in FILEPATH_BANLIST
}

LAYER_TO_SCAN_PATTERN = re.compile(r"\b(copy|add)\b", re.IGNORECASE)

TAG_PATTERN = re.compile(r":[a-zA-Z0-9_][-.a-zA-Z0-9_]{0,127}$")


class InvalidDockerArchiveException(Exception):
    pass


class DockerContentScannable(Scannable):
    """
    A Scannable for a file inside a Docker image
    """

    def __init__(
        self, layer_filename: str, tar_file: tarfile.TarFile, tar_info: tarfile.TarInfo
    ):
        super().__init__()
        self._layer_filename = layer_filename
        self._tar_file = tar_file
        self._tar_info = tar_info
        self._content: Optional[str] = None

    @property
    def url(self) -> str:
        # layer_filename is "<some_uuid>/layer.tar". We only keep "<some_uuid>"
        layer_name = os.path.dirname(self._layer_filename)
        return f"{layer_name}:/{self._tar_info.name}"

    @property
    def filename(self) -> str:
        return self.url

    @property
    def path(self) -> Path:
        return Path(self._tar_info.name)

    def is_longer_than(self, size: int) -> bool:
        if self._content:
            # We already have the content, easy
            return len(self._content) > size

        if self._tar_info.size < size:
            # Shortcut: if the byte size is smaller than `size`, we can be sure the
            # decoded size will be smaller
            return False

        # We need to decode at least the beginning of the file to determine if it's
        # small enough
        fp = self._tar_file.extractfile(self._tar_info)
        assert fp is not None
        with fp:
            result, self._content = Scannable._is_file_longer_than(
                fp, size  # type:ignore
            )
            # mypy complains that fp is IO[bytes] but _is_file_longer_than() expects
            # BinaryIO. They are compatible, ignore the error.
        return result

    @property
    def content(self) -> str:
        if self._content is None:
            file = self._tar_file.extractfile(self._tar_info)
            assert file is not None
            byte_content = file.read()
            self._content = Scannable._decode_bytes(byte_content)
        return self._content


class DockerFiles(Files):
    """A Files instance which keeps a reference to the TarFile storing the image
    content, so that we can continue to access it"""

    def __init__(self, tar_file: tarfile.TarFile):
        self.tar_file = tar_file
        manifest, config, config_file_to_scan = _get_config(self.tar_file)

        layer_files_to_scan = _get_layers_files(
            self.tar_file,
            filter(_should_scan_layer, _get_layer_infos(manifest, config)),
        )

        super().__init__(list(chain((config_file_to_scan,), layer_files_to_scan)))


def get_files_from_docker_archive(archive_path: Path) -> Files:
    """
    Extracts files to scan from a Docker image archive.
    Only the configuration and the layers generated with a `COPY` and `ADD`
    command are scanned.
    """
    return DockerFiles(tarfile.open(archive_path))


def _get_config(archive: tarfile.TarFile) -> Tuple[Dict, Dict, Scannable]:
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
        StringScannable("Dockerfile or build-args", config_file_content),
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
) -> Iterable[Scannable]:
    """
    Extracts File objects to be scanned for given layers.
    """
    for layer_info in layers_info:
        yield from _get_layer_files(archive, layer_info)


def _validate_filepath(
    filepath: str,
) -> bool:
    if any(
        banned_pattern.search(filepath) for banned_pattern in FILEPATH_BANLIST_PATTERNS
    ):
        return False

    if is_path_binary(filepath):
        return False
    return True


def _get_layer_files(archive: tarfile.TarFile, layer_info: Dict) -> Iterable[Scannable]:
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

        if file_info.size == 0:
            continue

        if not _validate_filepath(
            filepath=file_info.path,
        ):
            continue

        yield DockerContentScannable(layer_filename, layer_archive, file_info)


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
        raise UsageError(f'Image "{image_name}" not found')
    except subprocess.TimeoutExpired:
        raise UnexpectedError('Command "{}" timed out'.format(" ".join(command)))


def docker_save_to_tmp(image_name: str, destination_path: Path, timeout: int) -> None:
    """
    Do a `docker save <image_name> -o <destination_path>`

    Limit docker commands to run at most `timeout` seconds.
    """
    image_name = (
        image_name if TAG_PATTERN.search(image_name) else image_name + ":latest"
    )
    command = ["docker", "save", image_name, "-o", str(destination_path)]

    try:
        display_info("Saving docker image... ", nl=False)
        subprocess.run(
            command,
            check=True,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        display_info("OK")
    except subprocess.CalledProcessError as exc:
        err_string = str(exc.stderr)
        if "No such image" in err_string or "reference does not exist" in err_string:
            display_info("need to download image first")
            docker_pull_image(image_name, timeout)

            docker_save_to_tmp(image_name, destination_path, timeout)
        else:
            raise UnexpectedError(
                f"Unable to save docker archive:\nError: {err_string}"
            )
    except subprocess.TimeoutExpired:
        raise UnexpectedError('Command "{}" timed out'.format(" ".join(command)))


def docker_scan_archive(
    archive: Path,
    client: GGClient,
    cache: Cache,
    matches_ignore: Iterable[IgnoredMatch],
    scan_context: ScanContext,
    ignored_detectors: Optional[Set[str]] = None,
    ignore_known_secrets: Optional[bool] = None,
) -> ScanCollection:
    files = get_files_from_docker_archive(archive)

    with create_progress_bar(doc_type="files") as progress:

        scanner = SecretScanner(
            client=client,
            cache=cache,
            scan_context=scan_context,
            ignored_matches=matches_ignore,
            ignored_detectors=ignored_detectors,
            ignore_known_secrets=ignore_known_secrets,
        )
        task_scan = progress.add_task(
            "[green]Scanning Docker Image...", total=len(files.files)
        )
        results = scanner.scan(
            files.files,
            progress_callback=partial(progress.update, task_scan),
        )

    return ScanCollection(id=str(archive), type="scan_docker_archive", results=results)
