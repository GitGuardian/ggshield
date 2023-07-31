import sys
import tarfile
from io import BytesIO

from ggshield.core.file_utils import get_empty_tar


def test_get_empty_tar():
    # WHEN creating an empty tar
    empty_tar_bytes = get_empty_tar()
    tar_stream = BytesIO(empty_tar_bytes)

    # THEN the file is considered as a .tar
    version = sys.version_info
    # `tarfile.is_tarfile` won't work until Python 3.9
    if version.major > 3 or version.major == 3 and version.minor > 8:
        assert tarfile.is_tarfile(tar_stream)

    # AND it contains no file
    with tarfile.open(fileobj=tar_stream, mode="w:gz") as tar:
        assert len(tar.getmembers()) == 0
