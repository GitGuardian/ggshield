import os
import re
import tarfile
from io import BytesIO
from pathlib import Path

import click

from ggshield.core.constants import MAX_TAR_CONTENT_SIZE
from ggshield.scan import Files


POLICY_ID_PATTERN = re.compile("GG_IAC_[0-9]{4}")


def validate_policy_id(policy_id: str) -> bool:
    return bool(POLICY_ID_PATTERN.fullmatch(policy_id))


def create_tar(root_path: Path, files: Files) -> bytes:
    """
    :param root_path: the root_path from which the tar is created
    :param files: the files which need to be added to the tar, filenames should be the paths relative to the root_path
    :return: a bytes object containing the tar.gz created from the files, with paths relative to root_path
    """
    tar_stream = BytesIO()
    current_dir_size = 0
    with tarfile.open(fileobj=tar_stream, mode="w:gz") as tar:
        for filename in files.filenames:
            full_path = root_path / filename
            current_dir_size += os.path.getsize(full_path)
            if current_dir_size > MAX_TAR_CONTENT_SIZE:
                raise click.ClickException(
                    f"The total size of the files processed exceeds {MAX_TAR_CONTENT_SIZE / (1024 * 1024):.0f}MB, "
                    f"please try again with less files"
                )
            tar.add(full_path, filename)
    return tar_stream.getvalue()
