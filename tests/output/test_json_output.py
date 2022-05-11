from collections import namedtuple

import pytest

from ggshield.core.utils import Filemode, SupportedScanMode
from ggshield.output import JSONOutputHandler, OutputHandler
from ggshield.output.json.schemas import JSONScanCollectionSchema
from ggshield.scan import Commit, ScanCollection
from tests.conftest import (
    _MULTIPLE_SECRETS,
    _NO_SECRET,
    _ONE_LINE_AND_MULTILINE_PATCH,
    _SIMPLE_SECRET,
    _SINGLE_ADD_PATCH,
    _SINGLE_DELETE_PATCH,
    _SINGLE_MOVE_PATCH,
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
        ("multiple_secrets", _MULTIPLE_SECRETS, 1),
        ("simple_secret", _SIMPLE_SECRET, 1),
        ("test_scan_file_secret_with_validity", _SIMPLE_SECRET, 1),
        ("_ONE_LINE_AND_MULTILINE_PATCH", _ONE_LINE_AND_MULTILINE_PATCH, 1),
        ("no_secret", _NO_SECRET, 0),
        ("single_add", _SINGLE_ADD_PATCH, 1),
        ("single_delete", _SINGLE_DELETE_PATCH, 1),
        ("single_move", _SINGLE_MOVE_PATCH, 1),
    ],
    ids=[
        "_MULTIPLE_SECRETS",
        "_SIMPLE_SECRET",
        "_SIMPLE_SECRET-validity",
        "_ONE_LINE_AND_MULTILINE_PATCH",
        "_NO_SECRET",
        "_SINGLE_ADD_PATCH",
        "_SINGLE_DELETE_PATCH",
        "_SINGLE_MOVE_PATCH",
    ],
)
def test_json_output(client, cache, name, input_patch, expected, snapshot):
    c = Commit()
    c._patch = input_patch
    handler = JSONOutputHandler(verbose=True, show_secrets=False)

    with my_vcr.use_cassette(name):
        results = c.scan(
            client=client,
            cache=cache,
            matches_ignore={},
            all_policies=True,
            mode_header=SupportedScanMode.PATH.value,
            banlisted_detectors=None,
        )

        scan = ScanCollection(id="path", type="test", results=results)
        json_flat_results = handler._process_scan_impl(scan)
        exit_code = OutputHandler._get_exit_code(scan)

        assert exit_code == expected
        snapshot.assert_match(JSONScanCollectionSchema().loads(json_flat_results))
