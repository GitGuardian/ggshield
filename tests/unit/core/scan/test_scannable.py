from pathlib import Path

import pytest

from ggshield.core.scan import Files, StringScannable


def test_apply_filter():
    file1 = StringScannable(content="", url="file1")
    file2 = StringScannable(content="", url="file2")
    files = Files([file1, file2])

    filtered_files = files.apply_filter(lambda file: file.filename == "file1")
    assert len(filtered_files.files) == 1
    assert file1 in filtered_files.files


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
