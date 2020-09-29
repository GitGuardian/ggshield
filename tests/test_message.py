import pytest

from ggshield.message import leak_message, no_leak_message
from ggshield.scan import Filemode, Result

from .conftest import (
    _MULTI_SECRET_ONE_LINE_PATCH,
    _MULTI_SECRET_ONE_LINE_PATCH_OVERLAY,
    _MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT,
    _MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT,
    _MULTI_SECRET_TWO_LINES_PATCH,
    _MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT,
    _ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
    _ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
    _SIMPLE_SECRET_MULTILINE_PATCH,
    _SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT,
    _SIMPLE_SECRET_PATCH,
    _SIMPLE_SECRET_PATCH_SCAN_RESULT,
)


def test_message_no_secret(snapshot, capsys):
    no_leak_message()
    captured = capsys.readouterr()
    snapshot.assert_match(captured.out)


@pytest.mark.parametrize(
    "result_input",
    [
        pytest.param(
            Result(
                content=_SIMPLE_SECRET_PATCH,
                filename="leak.txt",
                filemode=Filemode.NEW,
                scan=_SIMPLE_SECRET_PATCH_SCAN_RESULT,
            ),
            id="_SIMPLE_SECRET_PATCH_SCAN_RESULT",
        ),
        pytest.param(
            Result(
                content=_MULTI_SECRET_ONE_LINE_PATCH,
                filename="leak.txt",
                filemode=Filemode.NEW,
                scan=_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT,
            ),
            id="_MULTI_SECRET_ONE_LINE_PATCH_SCAN_RESULT",
        ),
        pytest.param(
            Result(
                content=_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY,
                filename="leak.txt",
                filemode=Filemode.NEW,
                scan=_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT,
            ),
            id="_MULTI_SECRET_ONE_LINE_PATCH_OVERLAY_SCAN_RESULT",
        ),
        pytest.param(
            Result(
                content=_MULTI_SECRET_TWO_LINES_PATCH,
                filename="leak.txt",
                filemode=Filemode.NEW,
                scan=_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT,
            ),
            id="_MULTI_SECRET_TWO_LINES_PATCH_SCAN_RESULT",
        ),
        pytest.param(
            Result(
                content=_SIMPLE_SECRET_MULTILINE_PATCH,
                filename="leak.txt",
                filemode=Filemode.NEW,
                scan=_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT,
            ),
            id="_SIMPLE_SECRET_MULTILINE_PATCH_SCAN_RESULT",
        ),
        pytest.param(
            Result(
                content=_ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
                filename="leak.txt",
                filemode=Filemode.NEW,
                scan=_ONE_LINE_AND_MULTILINE_PATCH_SCAN_RESULT,
            ),
            id="_ONE_LINE_AND_MULTILINE_PATCH_CONTENT",
        ),
    ],
)
def test_leak_message(result_input, snapshot, capsys, client):
    leak_message(result_input, show_secrets=False)
    no_secret_captured = capsys.readouterr()
    snapshot.assert_match(no_secret_captured.out)

    leak_message(result_input, show_secrets=True)
    secret_captured = capsys.readouterr()
    snapshot.assert_match(secret_captured.out)
