import os
import tarfile
from io import BytesIO
from pathlib import Path
from typing import Iterable, Optional

from pygitguardian import ContentTooLarge
from pygitguardian.client import MAX_TAR_CONTENT_SIZE

from ggshield.utils.git_shell import check_git_ref, read_git_file


INDEX_REF = ""


def tar_from_ref_and_filepaths(
    ref: str,
    filepaths: Iterable[Path],
    wd: Optional[str] = None,
) -> bytes:
    """
    Builds a gzipped archive from a given git reference, and selected filepaths.
    The filepaths are typically obtained via `get_filepaths_from_ref` or `get_staged_filepaths`
    before being filtered.
    The archive is returned as raw bytes.
    :param ref: git reference, like a commit SHA, a relative reference like HEAD~1,\
        or any argument accepted as <ref> by git show <ref>:<filepath>
        An empty string denotes the git "index", aka staging area.
    :param filepaths: paths to selected files
    :param wd: string path to the git repository. Defaults to current directory
    """
    if not wd:
        wd = os.getcwd()

    # Empty string as ref makes the path valid for index
    if ref != INDEX_REF:
        check_git_ref(ref, wd)

    tar_stream = BytesIO()
    total_tar_size = 0

    with tarfile.open(fileobj=tar_stream, mode="w:gz") as tar:
        for path in filepaths:
            raw_file_content = read_git_file(ref, path, wd)
            data = BytesIO(raw_file_content.encode())

            tarinfo = tarfile.TarInfo(str(path))
            tarinfo.size = len(data.getbuffer())
            total_tar_size += tarinfo.size

            if total_tar_size > MAX_TAR_CONTENT_SIZE:
                raise ContentTooLarge(
                    f"The total size of the files processed exceeds {MAX_TAR_CONTENT_SIZE / (1024 * 1024):.0f}MB, "
                    f"please try again with less files"
                )

            tar.addfile(tarinfo, fileobj=data)

    return tar_stream.getvalue()


def get_empty_tar() -> bytes:
    bytes = BytesIO()
    file = tarfile.open(fileobj=bytes, mode="w:gz")
    file.close()
    return bytes.getvalue()
