from collections import namedtuple
from unittest.mock import Mock

import click
import pytest
from pygitguardian.models import Detail

from ggshield.core.errors import ExitCode, QuotaLimitReachedError
from ggshield.core.scan import (
    Commit,
    DecodeError,
    ScanContext,
    ScanMode,
    Scannable,
    StringScannable,
)
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.secret import SecretScanner, SecretScannerUI
from ggshield.verticals.secret.secret_scanner import handle_scan_chunk_error
from tests.unit.conftest import (
    _MULTIPLE_SECRETS_PATCH,
    _NO_SECRET_PATCH,
    _ONE_LINE_AND_MULTILINE_PATCH,
    GG_TEST_TOKEN,
    UNCHECKED_SECRET_PATCH,
    my_vcr,
)


ExpectedScan = namedtuple("expectedScan", "exit_code matches first_match want")
_EXPECT_NO_SECRET = {
    "content": "@@ -0,0 +1 @@\n+this is a patch without secret\n",
    "filename": "test.txt",
    "filemode": Filemode.NEW,
}


@pytest.mark.parametrize(
    "name,input_patch,expected",
    [
        (
            "multiple_secrets",
            _MULTIPLE_SECRETS_PATCH,
            ExpectedScan(
                ExitCode.SCAN_FOUND_PROBLEMS, matches=4, first_match="", want=None
            ),
        ),
        (
            "simple_secret",
            UNCHECKED_SECRET_PATCH,
            ExpectedScan(
                ExitCode.SCAN_FOUND_PROBLEMS,
                matches=1,
                first_match=GG_TEST_TOKEN,
                want=None,
            ),
        ),
        (
            "one_line_and_multiline_patch",
            _ONE_LINE_AND_MULTILINE_PATCH,
            ExpectedScan(
                ExitCode.SCAN_FOUND_PROBLEMS, matches=1, first_match=None, want=None
            ),
        ),
        (
            "no_secret",
            _NO_SECRET_PATCH,
            ExpectedScan(
                exit_code=0, matches=0, first_match=None, want=_EXPECT_NO_SECRET
            ),
        ),
    ],
    ids=[
        "_MULTIPLE_SECRETS",
        "_SIMPLE_SECRET",
        "_ONE_LINE_AND_MULTILINE_PATCH",
        "_NO_SECRET",
    ],
)
def test_scan_patch(client, cache, name, input_patch, expected):
    c = Commit()
    c._patch = input_patch

    with my_vcr.use_cassette(name):
        scanner = SecretScanner(
            client=client,
            cache=cache,
            scan_context=ScanContext(
                scan_mode=ScanMode.PATH,
                command_path="external",
            ),
        )
        results = scanner.scan(c.files)
        for result in results.results:
            if result.scan.policy_breaks:
                assert len(result.scan.policy_breaks[0].matches) == expected.matches
                if expected.first_match:
                    assert (
                        result.scan.policy_breaks[0].matches[0].match
                        == expected.first_match
                    )
            else:
                assert result.scan.policy_breaks == []

            if expected.want:
                assert result.content == expected.want["content"]
                assert result.filename == expected.want["filename"]
                assert result.filemode == expected.want["filemode"]


@pytest.mark.parametrize(
    "unscannable_type",
    [
        "EMPTY",
        "TOO_BIG",
        "BINARY",
    ],
)
def test_scanner_skips_unscannable_files(client, fs, cache, unscannable_type: str):
    """
    GIVEN a Scannable which is not scannable
    WHEN Scanner.scan() is called on it
    THEN it skips it
    AND the progress callback is called
    """
    mock = Mock(spec=Scannable)
    if unscannable_type == "EMPTY":
        mock.is_longer_than.return_value = False
        mock.content = ""
    elif unscannable_type == "TOO_BIG":
        mock.is_longer_than.return_value = True
    elif unscannable_type == "BINARY":
        mock.is_longer_than.side_effect = DecodeError

    scanner_ui = Mock(spec=SecretScannerUI)

    scanner = SecretScanner(
        client=client,
        cache=cache,
        scan_context=ScanContext(
            scan_mode=ScanMode.PATH,
            command_path="external",
        ),
        check_api_key=False,
    )
    scanner.scan([mock], scanner_ui=scanner_ui)

    scanner_ui.on_skipped.assert_called_once()


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


def test_handle_scan_quota_limit_reached():
    detail = Detail(detail="Quota limit reached.", status_code=403)
    with pytest.raises(QuotaLimitReachedError):
        handle_scan_chunk_error(detail, Mock())
