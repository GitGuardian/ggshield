from collections import namedtuple

import pytest
from pytest_voluptuous import Partial, S
from voluptuous import Optional, validators

from ggshield.core.utils import Filemode, ScanContext, ScanMode
from ggshield.output import JSONOutputHandler, OutputHandler
from ggshield.output.json.schemas import JSONScanCollectionSchema
from ggshield.scan import Commit, ScanCollection
from tests.conftest import (
    _MULTIPLE_SECRETS_PATCH,
    _NO_SECRET_PATCH,
    _ONE_LINE_AND_MULTILINE_PATCH,
    _SINGLE_ADD_PATCH,
    _SINGLE_DELETE_PATCH,
    _SINGLE_MOVE_PATCH,
    UNCHECKED_SECRET_PATCH,
    VALID_SECRET_PATCH,
    my_vcr,
)


ExpectedScan = namedtuple("expectedScan", "exit_code matches first_match want")

_EXPECT_NO_SECRET = {
    "content": "@@ -0,0 +1 @@\n+this is a patch without secret\n",
    "filename": "test.txt",
    "filemode": Filemode.NEW,
}

SCHEMA_WITHOUT_INCIDENTS = S(
    Partial(
        {
            "id": "path",
            "total_incidents": int,
            "total_occurrences": int,
            "type": "test",
        }
    )
)


SCHEMA_WITH_INCIDENTS = S(
    Partial(
        {
            "secrets_engine_version": validators.Match(r"\d\.\d{1,3}\.\d"),
            "results": validators.All(
                [
                    {
                        "filename": str,
                        "mode": validators.Any(
                            "MODIFY",
                            "RENAME",
                            "NEW",
                            "DELETE",
                            "PERMISSION_CHANGE",
                        ),
                        "total_incidents": validators.All(int, min=1),
                        "total_occurrences": validators.All(int, min=1),
                        Optional("validity"): validators.Any(
                            "valid",
                            "failed_to_check",
                            "invalid",
                            "not_checked",
                            "no_checker",
                        ),
                        "incidents": validators.All(
                            [
                                {
                                    "break_type": str,
                                    "policy": str,
                                    "total_occurrences": validators.All(int, min=1),
                                }
                            ],
                            validators.Length(min=1),
                        ),
                    }
                ],
                validators.Length(min=1),
            ),
        }
    )
)


@pytest.mark.parametrize(
    "name,input_patch,expected_exit_code",
    [
        ("multiple_secrets", _MULTIPLE_SECRETS_PATCH, 1),
        ("simple_secret", UNCHECKED_SECRET_PATCH, 1),
        ("test_scan_file_secret_with_validity", VALID_SECRET_PATCH, 1),
        ("one_line_and_multiline_patch", _ONE_LINE_AND_MULTILINE_PATCH, 1),
        ("no_secret", _NO_SECRET_PATCH, 0),
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
def test_json_output(client, cache, name, input_patch, expected_exit_code):
    c = Commit()
    c._patch = input_patch
    handler = JSONOutputHandler(verbose=True, show_secrets=False)

    with my_vcr.use_cassette(name):
        results = c.scan(
            client=client,
            cache=cache,
            matches_ignore={},
            scan_context=ScanContext(
                scan_mode=ScanMode.PATH,
                command_path="external",
            ),
            ignored_detectors=None,
        )

        scan = ScanCollection(id="path", type="test", results=results)
        json_flat_results = handler._process_scan_impl(scan)
        exit_code = OutputHandler._get_exit_code(scan)

        assert exit_code == expected_exit_code
        assert SCHEMA_WITHOUT_INCIDENTS == JSONScanCollectionSchema().loads(
            json_flat_results
        )
        if expected_exit_code:
            assert SCHEMA_WITH_INCIDENTS == JSONScanCollectionSchema().loads(
                json_flat_results
            )
