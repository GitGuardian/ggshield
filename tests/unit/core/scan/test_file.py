import codecs
from pathlib import Path
from random import randrange

import charset_normalizer
import pytest

from ggshield.core.scan import DecodeError, File
from ggshield.core.scan.file import create_files_from_paths
from tests.conftest import is_windows


UNICODE_TEST_CONTENT = "Ascii 123, accents: éèà, hiragana: ぁ, emoji: 🛡️"


def get_charset_normalizer_encoding(path: Path) -> str:
    """Returns the encoding that charset_normalizer would detect for `path`"""
    charset_match = charset_normalizer.from_path(path)
    assert charset_match
    return charset_match.best().encoding


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
    raw_content = bom + UNICODE_TEST_CONTENT.encode(encoding)
    path.write_bytes(raw_content)
    file = File(path)
    assert file.content == UNICODE_TEST_CONTENT


def test_file_does_not_decode_binary(tmp_path):
    """
    GIVEN a 2000 random bytes file
    WHEN File tries to decode it
    THEN it raises a DecodeError
    """
    path = tmp_path / "test.conf"
    data = (randrange(256) for _ in range(2000))
    path.write_bytes(bytes(data))

    file = File(path)
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

    file = File(path)
    with pytest.raises(DecodeError):
        file.is_longer_than(1000)


def test_file_is_longer_than_does_not_read_large_files(tmp_path):
    """
    GIVEN a File instance on a large file
    WHEN is_longer_than() is called on it
    THEN it returns the right value
    AND the content is not read
    """
    path = tmp_path / "test.conf"
    path.write_text(UNICODE_TEST_CONTENT * 1000, encoding="utf-8")

    file = File(path)
    assert file.is_longer_than(50)
    assert file._content is None


def test_file_is_longer_than_does_not_read_utf8_file(tmp_path):
    """
    GIVEN a File instance on either a small utf8 file
    WHEN is_longer_than() is called on it
    THEN it returns False
    AND the content is not read
    """
    path = tmp_path / "test.conf"
    path.write_text(UNICODE_TEST_CONTENT, encoding="utf-8")
    assert get_charset_normalizer_encoding(path) == "utf_8"

    file = File(path)
    assert not file.is_longer_than(1000)
    assert file._content is None


def test_file_is_longer_than_if_file_has_been_read(tmp_path):
    """
    GIVEN a File instance
    AND it has already read its file
    WHEN is_longer_than() is called on it
    THEN it returns the right value
    """
    path = tmp_path / "test.conf"
    content = "Mangé"
    path.write_text(content, encoding="utf-8")

    file = File(path)
    byte_content = path.stat().st_size

    # byte_content should be greater than len(content) because the *utf-8 encoded*
    # content is longer than the str content
    assert byte_content > len(content)

    # Force reading
    assert file.content == content

    assert file.is_longer_than(len(content))

    assert not file.is_longer_than(byte_content)


def test_file_is_longer_utf32(tmp_path):
    """
    GIVEN a file encoded in utf32, whose byte size is greater than N but whose utf8
    size is less than N
    WHEN is_longer_than(N) is called on it
    THEN it returns False
    AND the content is available because is_longer_than() read all the file
    """
    path = tmp_path / "test.conf"
    str_size = 200
    str_content = "x" * str_size

    byte_content = str_content.encode("utf32")
    path.write_bytes(byte_content)
    assert get_charset_normalizer_encoding(path) == "utf_32"

    # byte_content is longer than str_size because utf32 uses 4 bytes per code-point
    assert len(byte_content) > str_size

    file = File(path)
    assert not file.is_longer_than(len(byte_content))
    assert file._content == str_content


def test_file_is_longer_using_8bit_codec(tmp_path):
    """
    GIVEN a file encoded using an 8bit codec, whose byte size is less than N but whose
    utf8 size is greater than N
    WHEN is_longer_than(N) is called on it
    THEN it returns True
    """
    path = tmp_path / "test.conf"
    # Use characters that require more than one byte in utf8
    str_content = "écrit en français€"

    byte_content = str_content.encode("cp1250")
    path.write_bytes(byte_content)
    assert get_charset_normalizer_encoding(path) == "cp1250"

    # byte_content is shorter than str_content encoded as utf8 because cp1250 uses only
    # 1 byte per character
    assert len(byte_content) < len(str_content.encode())

    file = File(path)
    assert file.is_longer_than(len(byte_content))


def test_file_repr():
    """
    GIVEN a File instance
    WHEN repr() is called
    THEN it returns the correct output
    """
    if is_windows():
        str_path = r"c:\Windows"
        expected_url = "file:///c:/Windows"
    else:
        str_path = "/usr"
        expected_url = "file:///usr"
    file = File(Path(str_path))
    assert repr(file) == f"<File url={expected_url} filemode=Filemode.FILE>"


def test_file_path():
    """
    GIVEN an OS-specific path
    WHEN creating a File on it
    THEN file.path returns the correct path
    """
    str_path = r"c:\Windows" if is_windows() else "/usr"
    file = File(Path(str_path))
    assert file.path == Path(str_path)


@pytest.mark.parametrize(
    ["filename", "input_content", "expected_content"],
    [
        ("normal.txt", b"Normal", "Normal"),
        ("invalid-utf8-start-byte.txt", b"Hello\x81World", "Hello·World"),
        ("zero-bytes-are-kept.txt", b"Zero\0byte", "Zero\0byte"),
    ],
)
def test_create_files_from_paths(
    tmp_path, filename: str, input_content: bytes, expected_content: str
):
    """
    GIVEN a file
    WHEN calling create_files_from_paths() on it
    THEN it returns the expected File instance
    AND the content of the File instance is what is expected
    """
    path = tmp_path / filename
    path.write_bytes(input_content)

    files, _ = create_files_from_paths([path], exclusion_regexes=set())

    file = files[0]
    assert file.filename == str(path)
    assert file.content == expected_content

    assert len(files) == 1
