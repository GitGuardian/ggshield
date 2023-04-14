import json
import os.path
import re
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Set, Tuple

from click import UsageError
from pygitguardian import GGClient

from ggshield.core.cache import Cache
from ggshield.core.errors import UnexpectedError
from ggshield.core.file_utils import is_path_binary
from ggshield.core.text_utils import display_heading, display_info
from ggshield.core.types import IgnoredMatch
from ggshield.scan import (
    Files,
    RichSecretScannerUI,
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
        self, layer_id: str, tar_file: tarfile.TarFile, tar_info: tarfile.TarInfo
    ):
        super().__init__()
        self._layer_id = layer_id
        self._tar_file = tar_file
        self._tar_info = tar_info
        self._content: Optional[str] = None

    @property
    def url(self) -> str:
        return f"{self._layer_id}:/{self._tar_info.name}"

    @property
    def filename(self) -> str:
        return self.url

    @property
    def path(self) -> Path:
        return Path("/", self._tar_info.name)

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


@dataclass
class LayerInfo:
    filename: str
    command: str

    def get_id(self) -> str:
        # filename is "<layer_id>/layer.tar". We only keep "<layer_id>"
        return self.filename.split("/", maxsplit=1)[0]


class DockerImage:
    def __init__(self, tar_file: tarfile.TarFile):
        self.tar_file = tar_file
        self.manifest, self.config, self.config_scannable = _get_config(self.tar_file)

    def get_layers(self) -> Iterable[Tuple[LayerInfo, Files]]:
        for layer_info in filter(
            _should_scan_layer, _get_layer_infos(self.manifest, self.config)
        ):
            scannables = list(_get_layer_files(self.tar_file, layer_info))
            if scannables:
                yield (layer_info, Files(scannables))


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
) -> Iterable[LayerInfo]:
    """
    Returns LayerInfo instances for all non-empty layers
    """
    layer_filenames = manifest["Layers"]

    # config["history"] contains a list of entries like this:
    # {
    #   "created": ISO8601 timestamp,
    #   "created_by": command to build the layer
    #   "empty_layer": if present, equals true
    # }
    #
    # manifest["Layers"] contains a list of non-empty layers like this:
    #
    #   "<layer_id>/layer.tar"
    return (
        LayerInfo(filename=filename, command=layer.get("created_by", ""))
        for filename, layer in zip(
            layer_filenames,
            (layer for layer in config["history"] if not layer.get("empty_layer")),
        )
    )


def _should_scan_layer(layer_info: LayerInfo) -> bool:
    """
    Returns True if a layer should be scanned, False otherwise.
    Only COPY and ADD layers should be scanned.
    """
    if layer_info.command == "":
        # Some images contain layers with no commands. Since we don't know how they have
        # been created, we must scan them.
        # Examples of such images from Docker Hub:
        # - aevea/release-notary:0.9.7
        # - redhat/ubi8:8.6-754
        return True
    else:
        return LAYER_TO_SCAN_PATTERN.search(layer_info.command) is not None


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


def _get_layer_files(
    archive: tarfile.TarFile, layer_info: LayerInfo
) -> Iterable[Scannable]:
    """
    Extracts File objects to be scanned for given layer.
    """
    layer_filename = layer_info.filename
    layer_archive = tarfile.TarFile(
        name=os.path.join(archive.name, layer_filename),  # type: ignore
        fileobj=archive.extractfile(layer_filename),
    )

    layer_id = layer_info.get_id()

    for file_info in layer_archive:
        if not file_info.isfile():
            continue

        if file_info.size == 0:
            continue

        if not _validate_filepath(filepath=file_info.path):
            continue

        yield DockerContentScannable(layer_id, layer_archive, file_info)


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
    archive_path: Path,
    client: GGClient,
    cache: Cache,
    matches_ignore: Iterable[IgnoredMatch],
    scan_context: ScanContext,
    ignored_detectors: Optional[Set[str]] = None,
    ignore_known_secrets: Optional[bool] = None,
) -> ScanCollection:
    with tarfile.open(archive_path) as archive:
        docker_image = DockerImage(archive)

        scanner = SecretScanner(
            client=client,
            cache=cache,
            scan_context=scan_context,
            ignored_matches=matches_ignore,
            ignored_detectors=ignored_detectors,
            ignore_known_secrets=ignore_known_secrets,
        )
        display_heading("Scanning Docker config")
        with RichSecretScannerUI(1) as ui:
            results = scanner.scan(
                [docker_image.config_scannable],
                scanner_ui=ui,
            )

        for info, files in docker_image.get_layers():
            print()
            display_heading(f"Scanning layer {info.get_id()}")
            with RichSecretScannerUI(len(files.files)) as ui:
                results.extend(
                    scanner.scan(
                        files.files,
                        scanner_ui=ui,
                    )
                )

    return ScanCollection(id=str(archive), type="scan_docker_archive", results=results)
