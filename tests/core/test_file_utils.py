from pathlib import Path
from typing import Callable

import pytest

from ggshield.core.file_utils import generate_files_from_paths


@pytest.mark.parametrize(
    ["filename", "input_content", "expected_content"],
    [
        ("normal.txt", b"Normal", "Normal"),
        ("invalid-utf8-start-byte.txt", b"Hello\x81World", "Hello\uFFFDWorld"),
        ("zero-bytes-are-kept.txt", b"Zero\0byte", "Zero\0byte"),
    ],
)
def test_generate_files_from_paths(
    tmp_path, filename: str, input_content: bytes, expected_content: str
):
    """
    GIVEN a file
    WHEN calling generate_files_from_paths() on it
    THEN it returns the expected File instance
    AND the content of the File instance is what is expected
    """
    path = tmp_path / filename
    Path(path).write_bytes(input_content)

    files = list(generate_files_from_paths([str(path)], verbose=False))

    file = files[0]
    assert file.filename == str(path)
    assert file.document == expected_content

    assert len(files) == 1


@pytest.mark.parametrize(
    ["filename", "creator"],
    [
        ("a_binary_file.tar", lambda x: x.write_text("Uninteresting")),
        ("big_file", lambda x: x.write_text(2_000_000 * " ")),
        ("i_am_a_dir", lambda x: x.mkdir()),
    ],
)
def test_generate_files_from_paths_skips_files(
    tmp_path, filename: str, creator: Callable[[Path], None]
):
    """
    GIVEN a file which should be skipped
    WHEN calling generate_files_from_paths() on it
    THEN it should return an empty list
    """
    path = tmp_path / filename
    creator(path)

    files = list(generate_files_from_paths([str(path)], verbose=False))

    assert files == []
