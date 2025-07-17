from __future__ import annotations

import json
import re
import subprocess
import tarfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from click import UsageError

from ggshield.core import ui
from ggshield.core.dirs import get_cache_dir
from ggshield.core.errors import UnexpectedError
from ggshield.core.scan import Scannable, StringScannable
from ggshield.core.scan.id_cache import IDCache
from ggshield.core.scanner_ui import create_scanner_ui
from ggshield.utils.files import is_path_binary

from .secret_scan_collection import SecretScanCollection
from .secret_scanner import SecretScanner


if TYPE_CHECKING:
    from typing import Any, Dict, Generator, Iterable, List, Set

    from pygitguardian import GGClient

    from ggshield.core.cache import Cache
    from ggshield.core.config.user_config import SecretConfig
    from ggshield.core.scan import ScanContext

FILEPATH_BANLIST = [
    r"^/?usr/(?!share/nginx|src/app|app)",
    r"^/?lib/",
    r"^/?share/",
    r"^/?bin/",
    r"^/?sbin/",
    r"^/?node_modules/",
    r"^/?include/",
    r"^/?vendor/",
    r"^/?texlive/",
    r"^/?var/(?!www|src)",
    r"^/?fonts/",
    r"^/?npm/",
    r"^/?site-packages/",
]
FILEPATH_BANLIST_PATTERNS = {
    re.compile(banned_filepath) for banned_filepath in FILEPATH_BANLIST
}
# Note that FILEPATH_BANLIST_PATTERNS comes in addition to what's done in _exclude_callback

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

    @property
    def url(self) -> str:
        return f"{self._layer_id}:/{self._tar_info.name}"

    @property
    def filename(self) -> str:
        return self.url

    @property
    def path(self) -> Path:
        return Path("/", self._tar_info.name)

    def is_longer_than(self, max_utf8_encoded_size: int) -> bool:
        if self._utf8_encoded_size is not None:
            # We already have the encoded size, easy
            return self._utf8_encoded_size > max_utf8_encoded_size

        # We need to decode at least the beginning of the file to determine if it's
        # small enough
        fp = self._tar_file.extractfile(self._tar_info)
        assert fp is not None
        with fp:
            (
                result,
                self._content,
                self._utf8_encoded_size,
            ) = Scannable._is_file_longer_than(
                fp, max_utf8_encoded_size  # type:ignore
            )
            # mypy complains that fp is IO[bytes] but _is_file_longer_than() expects
            # BinaryIO. They are compatible, ignore the error.
        return result

    def _read_content(self) -> None:
        if self._content is None:
            file = self._tar_file.extractfile(self._tar_info)
            assert file is not None
            byte_content = file.read()
            self._content, self._utf8_encoded_size = Scannable._decode_bytes(
                byte_content
            )


@dataclass
class LayerInfo:
    filename: str
    command: str
    diff_id: str

    def should_scan(self) -> bool:
        """
        Returns True if a layer should be scanned, False otherwise.
        Only COPY and ADD layers should be scanned.
        """
        if self.command == "":
            # Some images contain layers with no commands. Since we don't know how they have
            # been created, we must scan them.
            # Examples of such images from Docker Hub:
            # - aevea/release-notary:0.9.7
            # - redhat/ubi8:8.6-754
            return True
        else:
            return LAYER_TO_SCAN_PATTERN.search(self.command) is not None


class DockerImage:
    # The manifest.json file
    manifest: Dict[str, Any]

    # The Image JSON file
    # (see https://github.com/moby/moby/blob/master/image/spec/v1.2.md#terminology)
    image: Dict[str, Any]

    layer_infos: List[LayerInfo]

    @staticmethod
    @contextmanager
    def open(archive_path: Path) -> Generator["DockerImage", None, None]:
        """ContextManager to create a DockerImage instance."""
        with tarfile.open(archive_path) as tar_file:
            yield DockerImage(archive_path, tar_file)

    def __init__(self, archive_path: Path, tar_file: tarfile.TarFile):
        """Creates a DockerImage instance. Internal. Prefer using DockerImage.open()."""
        self.archive_path = archive_path
        self.tar_file = tar_file
        self._load_manifest()
        self._load_image()
        self.config_scannable = StringScannable(
            "Dockerfile or build-args", json.dumps(self.image, indent=2)
        )

        self._load_layer_infos()

    def _load_manifest(self) -> None:
        """
        Reads "manifest.json", stores result in self.manifest
        """
        manifest_file = self.tar_file.extractfile("manifest.json")
        if manifest_file is None:
            raise InvalidDockerArchiveException("No manifest file found.")

        self.manifest = json.load(manifest_file)[0]

    def _load_image(self) -> None:
        """
        Reads the image JSON file, stores result in self.image
        """
        try:
            config_file_path = self.manifest["Config"]
        except KeyError:
            raise InvalidDockerArchiveException("No Config key in manifest.")

        config_file_info = self.tar_file.getmember(config_file_path)
        if config_file_info is None:
            raise InvalidDockerArchiveException("No config file found.")

        config_file = self.tar_file.extractfile(config_file_info)
        if config_file is None:
            raise InvalidDockerArchiveException("Config file could not be extracted.")

        self.image = json.load(config_file)

    def _load_layer_infos(self) -> None:
        """
        Fill self.layer_infos with LayerInfo instances for all non-empty layers
        """

        #
        # manifest["Layers"] contains a list of non-empty layers like this:
        #
        #   "<random_id>/layer.tar"
        layer_filenames = self.manifest["Layers"]

        # image["history"] contains a list of entries like this:
        # {
        #   "created": ISO8601 timestamp,
        #   "created_by": command to build the layer
        #   "empty_layer": if present, equals true
        # }
        non_empty_history_entries = [
            x for x in self.image["history"] if not x.get("empty_layer")
        ]

        #
        # image["rootfs"]["diff_ids"] contains the list of layer IDs
        diff_ids = self.image["rootfs"]["diff_ids"]

        layer_infos = [
            LayerInfo(
                filename=filename,
                command=history.get("created_by", ""),
                diff_id=diff_id,
            )
            for filename, history, diff_id in zip(
                layer_filenames, non_empty_history_entries, diff_ids
            )
        ]
        self.layer_infos = [x for x in layer_infos if x.should_scan()]

    def get_layer_scannables(
        self, layer_info: LayerInfo, exclusion_regexes: Set[re.Pattern[str]]
    ) -> Iterable[Scannable]:
        """
        Extracts Scannable to be scanned for given layer.
        """
        layer_filename = layer_info.filename
        layer_archive = tarfile.open(
            name=self.archive_path / layer_filename,
            fileobj=self.tar_file.extractfile(layer_filename),
        )

        layer_id = layer_info.diff_id

        for file_info in layer_archive:
            if not file_info.isfile():
                continue

            if file_info.size == 0:
                continue

            if not _validate_filepath(
                filepath=file_info.path, exclusion_regexes=exclusion_regexes
            ):
                continue

            yield DockerContentScannable(layer_id, layer_archive, file_info)


def _validate_filepath(
    filepath: str,
    exclusion_regexes: Set[re.Pattern[str]],
) -> bool:
    if any(
        banned_pattern.search(filepath)
        for banned_pattern in FILEPATH_BANLIST_PATTERNS | exclusion_regexes
    ):
        return False

    if is_path_binary(filepath):
        return False
    return True


def _get_layer_id_cache(secrets_engine_version: str) -> IDCache:
    cache_path = get_cache_dir() / "docker" / f"{secrets_engine_version}.json"
    return IDCache(cache_path)


def docker_pull_image(image_name: str, timeout: int) -> None:
    """
    Pull docker image and raise exception on timeout or failed to find image

    Timeout after `timeout` seconds.
    """
    # Base command for docker pull
    base_command = ["docker", "pull", image_name]

    # Try standard pull first
    if _run_docker_command(base_command, timeout):
        return

    # Fall back to linux/amd64 if no success
    amd64_command = base_command + ["--platform=linux/amd64"]
    if _run_docker_command(amd64_command, timeout):
        return

    # Raise error if no success
    raise UsageError(f'Image "{image_name}" not found')


def _run_docker_command(command: List[str], timeout: int) -> bool:
    """
    Run a docker command with timeout and return success status

    Args:
        command: Docker command to run as a list of strings
        timeout: Timeout in seconds

    Returns:
        True if command succeeded, False if CalledProcessError

    Raises:
        UnexpectedError: If command times out
    """
    try:
        subprocess.run(
            command,
            check=True,
            timeout=timeout,
        )
        return True
    except subprocess.CalledProcessError:
        return False
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
        ui.display_info("Saving docker image...")
        subprocess.run(
            command,
            check=True,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        ui.display_info("OK")
    except subprocess.CalledProcessError as exc:
        err_string = str(exc.stderr)
        if "No such image" in err_string or "reference does not exist" in err_string:
            ui.display_info("need to download image first")
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
    secret_config: SecretConfig,
    scan_context: ScanContext,
    exclusion_regexes: Set[re.Pattern[str]],
) -> SecretScanCollection:
    scanner = SecretScanner(
        client=client,
        cache=cache,
        scan_context=scan_context,
        secret_config=secret_config,
    )
    secrets_engine_version = client.secrets_engine_version
    assert secrets_engine_version is not None
    layer_id_cache = _get_layer_id_cache(secrets_engine_version)

    with DockerImage.open(archive_path) as docker_image:
        ui.display_heading("Scanning Docker config")
        with create_scanner_ui(1) as scanner_ui:
            results = scanner.scan(
                [docker_image.config_scannable], scanner_ui=scanner_ui
            )

        for info in docker_image.layer_infos:
            files = list(docker_image.get_layer_scannables(info, exclusion_regexes))
            file_count = len(files)
            if file_count == 0:
                continue
            print()
            layer_id = info.diff_id
            if layer_id in layer_id_cache:
                ui.display_heading(f"Skipping layer {layer_id}: already scanned")
            else:
                ui.display_heading(f"Scanning layer {info.diff_id}")
                with create_scanner_ui(file_count) as scanner_ui:
                    layer_results = scanner.scan(files, scanner_ui=scanner_ui)
                if not layer_results.has_secrets:
                    layer_id_cache.add(layer_id)
                results.extend(layer_results)

    return SecretScanCollection(
        id=str(archive_path), type="scan_docker_archive", results=results
    )
