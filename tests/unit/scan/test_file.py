import codecs
from pathlib import Path
from random import randrange

import pytest

from ggshield.scan import DecodeError, File
from ggshield.scan.file import generate_files_from_paths
from tests.conftest import is_windows


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
    file = File(str(path))
    assert file.content == content


def test_file_does_not_decode_binary(tmp_path):
    """
    GIVEN a 2000 random bytes file
    WHEN File tries to decode it
    THEN it raises a DecodeError
    """
    path = tmp_path / "test.conf"
    data = (randrange(256) for _ in range(2000))
    path.write_bytes(bytes(data))

    file = File(str(path))
    with pytest.raises(DecodeError):
        _dummy = file.content  # noqa (mute "_dummy" is never used)


def test_file_is_longer_does_not_decode_binary(tmp_path):
    """
    GIVEN a 2000 random bytes file
    WHEN is_longer_than() is called on it
    THEN it raises a DecodeError
    """
    path = tmp_path / "test.conf"
    data = (randrange(256) for _ in range(2000))
    path.write_bytes(bytes(data))

    file = File(str(path))
    with pytest.raises(DecodeError):
        file.is_longer_than(1000)


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

    file = File(str(path))
    assert file.is_longer_than(50) == (size > 50)
    assert file._content is None


def test_file_is_longer_when_file_has_been_read(tmp_path):
    """
    GIVEN a File instance
    AND it has already read its file
    WHEN is_longer_than() is called on it
    THEN it returns the right value
    """
    path = tmp_path / "test.conf"
    content = "x" * 100
    path.write_text(content)

    file = File(str(path))
    # Force reading
    assert file.content == content

    assert file.is_longer_than(50)


def test_file_is_longer_use_decoded_size(tmp_path):
    """
    GIVEN a file encoded in utf32, whose byte size is greater than N but whose string
    size is smaller than N
    WHEN is_longer_than(N) is called on it
    THEN it returns False
    AND the content is available because is_longer_than() read all the file
    """
    path = tmp_path / "test.conf"
    str_size = 200
    str_content = "x" * str_size
    byte_content = str_content.encode("utf32")
    path.write_bytes(byte_content)

    # byte_content should be longer than max_str_size because utf32 uses 4 bytes per
    # code-point
    max_str_size = str_size + 10
    assert max_str_size < len(byte_content)

    file = File(str(path))
    assert not file.is_longer_than(max_str_size)
    assert file._content == str_content


def test_file_repr():
    """
    GIVEN a File instance
    WHEN repr() is called
    THEN it returns the correct output
    """
    if is_windows():
        str_path = r"c:\Windows"
        expected_url = "file://c:/Windows"
    else:
        str_path = "/usr"
        expected_url = "file:///usr"
    file = File(str_path)
    assert repr(file) == f"<File url={expected_url} filemode=Filemode.FILE>"


def test_file_path():
    """
    GIVEN an OS-specific path
    WHEN creating a File on it
    THEN file.path returns the correct path
    """
    str_path = r"c:\Windows" if is_windows() else "/usr"
    file = File(str_path)
    assert file.path == Path(str_path)


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
