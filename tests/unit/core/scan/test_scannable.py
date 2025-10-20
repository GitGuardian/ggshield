from pathlib import Path
from unittest.mock import patch

import pytest

from ggshield.core.scan import File, StringScannable
from ggshield.core.scan.scannable import NonSeekableFileError


def test_string_scannable_path():
    """
    GIVEN a StringScannable instance
    WHEN path() is called
    THEN it returns the right value
    """
    scannable = StringScannable(url="custom:/some/path", content="")
    assert scannable.path == Path("/some/path")


@pytest.mark.parametrize(
    ("content", "is_longer"),
    (
        ("x" * 100, True),
        ("x" * 10, False),
        ("é" * 40, True),  # Longer than 50 as utf-8
        ("\uD800", False),  # Triggers an encoding error
    ),
)
def test_string_scannable_is_longer_than(content, is_longer):
    """
    GIVEN a StringScannable
    WHEN is_longer_than() is called
    THEN it returns the expected value
    """
    scannable = StringScannable(content=content, url="u")
    assert scannable.is_longer_than(50) == is_longer


@patch("pathlib.Path.open")
def test_file_non_seekable(mock_open, tmp_path):
    """
    GIVEN a File instance
    AND the file reports as seekable but seeking operations fail
    WHEN is_longer_than() is called on it
    THEN it raises NonSeekableFileError
    """
    mock_file = mock_open.return_value.__enter__.return_value
    mock_file.seekable.return_value = True
    mock_file.seek.side_effect = OSError(22, "Invalid argument")

    test_file = tmp_path / "test.txt"
    test_file.write_text("test content")
    file_obj = File(test_file)

    with pytest.raises(NonSeekableFileError):
        file_obj.is_longer_than(1000)
