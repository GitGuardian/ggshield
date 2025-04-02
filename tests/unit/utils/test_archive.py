from pathlib import Path
from typing import Optional
from zipfile import ZipFile

import pytest

from ggshield.utils.archive import (
    UnsafeArchive,
    _zip_get_symlink_target,
    check_archive_content,
    safe_unpack,
)
from tests.unit.conftest import DATA_PATH


ARCHIVES_PATH = DATA_PATH / "archives"
BAD_ZIP_PATH = ARCHIVES_PATH / "bad.zip"
BAD_TAR_PATH = ARCHIVES_PATH / "bad.tar"
BAD_JAR_PATH = ARCHIVES_PATH / "bad.jar"
GOOD_ZIP_PATH = ARCHIVES_PATH / "good.zip"
GOOD_WHL_PATH = ARCHIVES_PATH / "good.whl"
GOOD_TAR_PATH = ARCHIVES_PATH / "good.tar"
GOOD_JAR_PATH = ARCHIVES_PATH / "good.jar"

"""
Both bad.zip, bad.tar, and bad.jar have the same content:

./
./fine
./subdir/
./subdir/bad-relative-symlink -> ../../bad-relative
./subdir/bad-absolute-symlink -> /tmp/bad-absolute
./subdir/fine-symlink -> ../fine
../bad-relative
/tmp/bad-absolute
"""


@pytest.mark.parametrize("archive", [BAD_ZIP_PATH, BAD_TAR_PATH, BAD_JAR_PATH])
def test_check_archive_content_raises_exception(archive: Path):
    """
    GIVEN a bad archive
    WHEN check_archive_content() is called
    THEN it raises an exception
    AND the exception contains the description of what's bad in the archive
    """
    with pytest.raises(UnsafeArchive) as exc_info:
        check_archive_content(archive)

    bad_paths = set(exc_info.value.bad_paths)
    assert bad_paths == {Path("../bad-relative"), Path("/tmp/bad-absolute")}

    bad_links = set(exc_info.value.bad_links)
    assert bad_links == {
        (Path("./subdir/bad-relative-symlink"), Path("../../bad-relative")),
        (Path("./subdir/bad-absolute-symlink"), Path("/tmp/bad-absolute")),
    }

    # Basic message check, ensures __str__() is exercised
    message = str(exc_info.value)
    assert "Paths outside the archive root:" in message
    assert "bad-relative" in message
    assert "Links pointing outside the archive root:" in message
    assert "bad-absolute-symlink" in message


@pytest.mark.parametrize(
    "archive", [GOOD_ZIP_PATH, GOOD_WHL_PATH, GOOD_TAR_PATH, GOOD_JAR_PATH]
)
def test_check_safe_unpack(tmp_path: Path, archive: Path):
    """
    GIVEN a good archive
    WHEN safe_unpack() is called
    THEN it unpacks the archive
    """
    safe_unpack(archive, tmp_path)
    unpacked_files = set(p for p in tmp_path.rglob("*") if not p.is_dir())
    assert unpacked_files == {tmp_path / "fine", tmp_path / "subdir/fine-symlink"}


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("./subdir/fine-symlink", Path("../fine")),
        ("./fine", None),
    ],
)
def test_zip_get_symlink_target(name: str, target: Optional[Path]):
    """
    GIVEN a path inside bad.zip
    WHEN asked for its symlink target
    THEN it returns the target if it's a symlink, or None if it's a regular file
    """
    with ZipFile(BAD_ZIP_PATH) as zip:
        info = zip.getinfo(name)
        assert _zip_get_symlink_target(zip, info) == target
