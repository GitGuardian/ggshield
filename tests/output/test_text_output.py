from copy import deepcopy
from unittest import mock

import click
import pytest

from ggshield.core.utils import Filemode
from ggshield.output import TextOutputHandler
from ggshield.output.text.message import (
    _file_info_decoration,
    _file_info_default_decoration,
)
from ggshield.scan import Result
from ggshield.scan.scannable import Results, ScanCollection
from tests.conftest import (
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


@pytest.mark.parametrize(
    "show_secrets",
    [pytest.param(True, id="show_secrets"), pytest.param(False, id="hide_secrets")],
)
@pytest.mark.parametrize(
    "verbose",
    [pytest.param(True, id="verbose"), pytest.param(False, id="clip_long_lines")],
)
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
def test_leak_message(result_input, snapshot, show_secrets, verbose):
    # The text output includes the version of the secrets engine, but this version is
    # None until we make an API call. Since this test does not make any API call, set
    # the version to a fake value.
    with mock.patch("ggshield.output.text.message.VERSIONS") as VERSIONS:
        VERSIONS.secrets_engine_version = "3.14.159"

        output_handler = TextOutputHandler(show_secrets=show_secrets, verbose=verbose)

        # _process_scan_impl() modifies its ScanCollection arg(!), so make a copy of it
        new_result = deepcopy(result_input)

        output = output_handler._process_scan_impl(
            ScanCollection(
                id="scan",
                type="test",
                results=Results(results=[new_result], errors=[]),
                optional_header="> This is an example header",
            )
        )
    # Make output OS-independent, so that it can be safely compared to snapshots
    # regardless of the current OS:
    # - Remove colors because color codes are not the same on all OSes
    # - Replace any custom decoration with the default one
    output = click.unstyle(output).replace(
        _file_info_decoration(), _file_info_default_decoration()
    )

    snapshot.assert_match(output)
