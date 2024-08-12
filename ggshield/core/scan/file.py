from pathlib import Path
from typing import List, Pattern, Set, Tuple, Union

from ggshield.utils.files import ListFilesMode, is_path_binary, list_files, url_for_path

from .scannable import Scannable


class File(Scannable):
    """Implementation of Scannable for files from the disk."""

    def __init__(self, path: Union[str, Path]):
        super().__init__()
        self._path = Path(path)

    @property
    def url(self) -> str:
        return url_for_path(self._path)

    @property
    def filename(self) -> str:
        return str(self._path)

    @property
    def path(self) -> Path:
        return self._path

    def is_longer_than(self, max_utf8_encoded_size: int) -> bool:
        if self._utf8_encoded_size is not None:
            # We already have the encoded size, easy
            return self._utf8_encoded_size > max_utf8_encoded_size

        with self.path.open("rb") as fp:
            (
                result,
                self._content,
                self._utf8_encoded_size,
            ) = Scannable._is_file_longer_than(fp, max_utf8_encoded_size)
        return result

    def _read_content(self) -> None:
        if self._content is None:
            with self.path.open("rb") as f:
                self._content, self._utf8_encoded_size = Scannable._decode_bytes(
                    f.read()
                )


def create_files_from_paths(
    paths: List[Path],
    exclusion_regexes: Set[Pattern[str]],
    list_files_mode: ListFilesMode = ListFilesMode.GIT_COMMITTED_OR_STAGED,
) -> Tuple[List[Scannable], List[Path]]:
    """
    Create File instances for `paths` and return them, as well as a list of the ignored
    paths found in `paths`.
    """
    filepaths = list_files(
        paths,
        exclusion_regexes,
        list_files_mode=list_files_mode,
    )

    files: List[Scannable] = []
    binary_paths: List[Path] = []
    for path in filepaths:
        if is_path_binary(path):
            binary_paths.append(path)
            continue

        files.append(File(path))

    return (files, binary_paths)
