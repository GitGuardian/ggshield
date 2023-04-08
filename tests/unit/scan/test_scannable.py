from pathlib import Path

import click
import pytest
from pygitguardian.models import Detail

from ggshield.scan import Files, StringScannable
from ggshield.scan.scanner import handle_scan_chunk_error


def test_apply_filter():
    file1 = StringScannable(content="", url="file1")
    file2 = StringScannable(content="", url="file2")
    files = Files([file1, file2])

    filtered_files = files.apply_filter(lambda file: file.filename == "file1")
    assert len(filtered_files.files) == 1
    assert file1 in filtered_files.files


def test_handle_scan_error_api_key():
    detail = Detail("Invalid API key.")
    detail.status_code = 401
    with pytest.raises(click.UsageError):
        handle_scan_chunk_error(detail, [])


@pytest.mark.parametrize(
    "detail, status_code, chunk",
    [
        pytest.param(
            Detail("Too many documents to scan"),
            400,
            [StringScannable(content="", url="/example") for _ in range(21)],
            id="too many documents",
        ),
        pytest.param(
            Detail(
                "[\"filename:: [ErrorDetail(string='Ensure this field has no more than 256 characters.', code='max_length')]\", '', '', '']"  # noqa
            ),
            400,
            [
                StringScannable(
                    content="still valid", url="/home/user/too/long/file/name"
                ),
                StringScannable(content="", url="valid"),
                StringScannable(content="", url="valid"),
                StringScannable(content="", url="valid"),
            ],
            id="single file exception",
        ),
    ],
)
def test_handle_scan_error(detail, status_code, chunk, capsys, snapshot):
    detail.status_code = 400
    handle_scan_chunk_error(detail, chunk)
    captured = capsys.readouterr()
    snapshot.assert_match(captured.err)


def test_string_scannable_path():
    """
    GIVEN a StringScannable instance
    WHEN path() is called
    THEN it returns the right value
    """
    scannable = StringScannable(url="custom:/some/path", content="")
    assert scannable.path == Path("/some/path")
