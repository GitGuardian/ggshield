from pathlib import Path

from ggshield.scan import Files, StringScannable


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
