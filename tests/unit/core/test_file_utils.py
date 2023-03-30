import codecs
from pathlib import Path
from random import randrange

import pytest

from ggshield.core.file_utils import generate_files_from_paths
from ggshield.scan import File


@pytest.mark.parametrize(
    ["filename", "input_content", "expected_content"],
    [
        ("normal.txt", b"Normal", "Normal"),
        ("invalid-utf8-start-byte.txt", b"Hello\x81World", "Hello·World"),
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
    assert file.content == expected_content

    assert len(files) == 1


@pytest.mark.parametrize(
    ["encoding", "bom"],
    [
        ("utf-8", b""),
        ("utf-8", codecs.BOM_UTF8),
        ("utf-16-be", b""),
        ("utf-16-be", codecs.BOM_UTF16_BE),
        ("utf-16-le", b""),
        ("utf-16-le", codecs.BOM_UTF16_LE),
        ("utf-32-be", b""),
        ("utf-32-be", codecs.BOM_UTF32_BE),
        ("utf-32-le", b""),
        ("utf-32-le", codecs.BOM_UTF32_LE),
    ],
)
def test_file_decode_content(tmp_path, encoding: str, bom: bytes):
    """
    GIVEN a valid utf encoded file, with or without a BOM
    WHEN FILE tries to decode it
    THEN it succeeds
    """
    path = tmp_path / "test.conf"
    content = "Ascii 123, accents: éèà, hiragana: ぁ, emoji: 🛡️"
    raw_content = bom + content.encode(encoding)
    path.write_bytes(raw_content)
    file = File.from_path(str(path))
    assert file.content == content


def test_file_does_not_decode_binary(tmp_path):
    """
    GIVEN a 2000 random bytes file
    WHEN File tries to decode it
    THEN it fails
    AND set its `content` attribute to ""
    """
    path = tmp_path / "test.conf"
    data = (randrange(256) for _ in range(2000))
    path.write_bytes(bytes(data))

    file = File.from_path(str(path))
    assert file.content == ""


@pytest.mark.parametrize("size", [1, 100])
def test_file_is_longer_than_does_not_read_file(tmp_path, size):
    """
    GIVEN a File instance
    WHEN is_longer_than() is called on it
    THEN it returns the right value
    AND the content is not read
    """
    path = tmp_path / "test.conf"
    path.write_text("x" * size)

    file = File.from_path(str(path))
    assert file.is_longer_than(50) == (size > 50)
    assert file._content is None
