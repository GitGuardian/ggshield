import click
import pytest
from pygitguardian.models import Detail

from ggshield.scan.scannable_errors import handle_scan_error


def test_handle_scan_error_api_key():
    detail = Detail("Invalid API key.")
    detail.status_code = 401
    with pytest.raises(click.UsageError):
        handle_scan_error(detail, [])


@pytest.mark.parametrize(
    "detail, status_code, chunk",
    [
        pytest.param(
            Detail("Too many documents to scan"),
            400,
            [{"document": "", "filename": "/example"} for _ in range(21)],
            id="too many documents",
        ),
        pytest.param(
            Detail(
                "[\"filename:: [ErrorDetail(string='Ensure this field has no more than 256 characters.', code='max_length')]\", '', '', '']"  # noqa
            ),
            400,
            [
                {
                    "document": "still valid",
                    "filename": "/home/user/too/long/file/name",
                },
                {"document": "", "filename": "valid"},
                {"document": "", "filename": "valid"},
                {"document": "", "filename": "valid"},
            ],
            id="single file exception",
        ),
    ],
)
def test_handle_scan_error(detail, status_code, chunk, capsys, snapshot):
    detail.status_code = 400
    handle_scan_error(detail, chunk)
    captured = capsys.readouterr()
    snapshot.assert_match(captured.err)
