import json
import operator
from collections import namedtuple
from copy import deepcopy
from typing import Any, Dict, List, Optional, TypedDict
from unittest.mock import Mock

import pytest
from pytest_voluptuous import Partial, S
from voluptuous import Optional as VOptional
from voluptuous import Required, validators

from ggshield.core.filter import group_policy_breaks_by_ignore_sha
from ggshield.core.scan import Commit, ScanContext, ScanMode, StringScannable
from ggshield.utils.git_shell import Filemode
from ggshield.verticals.secret import (
    Result,
    Results,
    SecretScanCollection,
    SecretScanner,
)
from ggshield.verticals.secret.output import (
    SecretJSONOutputHandler,
    SecretOutputHandler,
)
from tests.unit.conftest import (
    _MULTIPLE_SECRETS_PATCH,
    _NO_SECRET_PATCH,
    _ONE_LINE_AND_MULTILINE_PATCH,
    _ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
    _SINGLE_ADD_PATCH,
    _SINGLE_DELETE_PATCH,
    _SINGLE_MOVE_PATCH,
    TWO_POLICY_BREAKS,
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
            "entities_with_incidents": validators.All(
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
                        VOptional("validity"): validators.Any(
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
                                    Required("incident_url"): validators.Match(
                                        r"^($|https://)"
                                    ),
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


class ExpectedIndicesDict(TypedDict):
    line_start: int
    line_end: int
    pre_line_start: Optional[int]
    pre_line_end: Optional[int]
    post_line_start: Optional[int]
    post_line_end: Optional[int]


MATCH_INDICES_FOR_PATCH: Dict[str, List[ExpectedIndicesDict]] = {
    # The "* 4" is there because this is a 4-matches secret, but the JSON output uses
    # the line_start and line_end from the server, which uses the line numbers of the
    # first match for all matches!
    _MULTIPLE_SECRETS_PATCH: [
        {
            "line_start": 2,
            "line_end": 2,
            "pre_line_start": None,
            "pre_line_end": None,
            "post_line_start": 2,
            "post_line_end": 2,
        }
    ]
    * 4,
    UNCHECKED_SECRET_PATCH: [
        {
            "line_start": 2,
            "line_end": 2,
            "pre_line_start": None,
            "pre_line_end": None,
            "post_line_start": 2,
            "post_line_end": 2,
        }
    ],
    VALID_SECRET_PATCH: [
        {
            "line_start": 2,
            "line_end": 2,
            "pre_line_start": None,
            "pre_line_end": None,
            "post_line_start": 2,
            "post_line_end": 2,
        }
    ],
    _ONE_LINE_AND_MULTILINE_PATCH: [
        {
            "line_start": 1,
            "line_end": 9,
            "pre_line_start": None,
            "pre_line_end": None,
            "post_line_start": 1,
            "post_line_end": 9,
        },
        {
            "line_start": 9,
            "line_end": 9,
            "pre_line_start": None,
            "pre_line_end": None,
            "post_line_start": 9,
            "post_line_end": 9,
        },
    ],
    _SINGLE_ADD_PATCH: [
        {
            "line_start": 1,
            "line_end": 1,
            "pre_line_start": None,
            "pre_line_end": None,
            "post_line_start": 1,
            "post_line_end": 1,
        }
    ],
    _SINGLE_DELETE_PATCH: [
        {
            "line_start": 2,
            "line_end": 2,
            "pre_line_start": 2,
            "pre_line_end": 2,
            "post_line_start": None,
            "post_line_end": None,
        }
    ],
    _SINGLE_MOVE_PATCH: [
        {
            "line_start": 150,
            "line_end": 150,
            "pre_line_start": 150,
            "pre_line_end": 150,
            "post_line_start": 151,
            "post_line_end": 151,
        }
    ],
}


def create_occurrence_indices_dict(occurrence: Dict[str, Any]) -> ExpectedIndicesDict:
    return {k: occurrence.get(k) for k in ExpectedIndicesDict.__annotations__.keys()}


def check_occurrences_indices(occurrences: List[Dict[str, Any]], patch: str) -> None:
    """
    Check `occurrences` contains the expected indices for patch `patch`.
    """
    match_indices_list = MATCH_INDICES_FOR_PATCH[patch]

    line_start_getter = operator.itemgetter("line_start")

    occurrences_indices_list = [create_occurrence_indices_dict(x) for x in occurrences]
    assert sorted(occurrences_indices_list, key=line_start_getter) == sorted(
        match_indices_list, key=line_start_getter
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
    c = Commit.from_patch(input_patch)
    handler = SecretJSONOutputHandler(verbose=True, show_secrets=False)

    with my_vcr.use_cassette(name):
        scanner = SecretScanner(
            client=client,
            cache=cache,
            scan_context=ScanContext(
                scan_mode=ScanMode.PATH,
                command_path="external",
            ),
        )
        results = scanner.scan(c.get_files(), scanner_ui=Mock())

        scan = SecretScanCollection(id="path", type="test", results=deepcopy(results))
        json_flat_results = handler._process_scan_impl(scan)
        exit_code = SecretOutputHandler._get_exit_code(
            Mock(ignore_known_secrets=False), scan
        )

        assert exit_code == expected_exit_code
        json_dict = json.loads(json_flat_results)
        assert SCHEMA_WITHOUT_INCIDENTS == json_dict
        if expected_exit_code:
            assert SCHEMA_WITH_INCIDENTS == json_dict

            occurrences = [
                occurrence
                for result in json_dict["entities_with_incidents"]
                for incident in result["incidents"]
                for occurrence in incident["occurrences"]
            ]
            check_occurrences_indices(occurrences, input_patch)

        # all ignore sha should be in the output
        assert all(
            ignore_sha in json_flat_results
            for result in results.results
            for ignore_sha in group_policy_breaks_by_ignore_sha(
                result.scan.policy_breaks
            )
        )


@pytest.mark.parametrize("verbose", [True, False])
@pytest.mark.parametrize("ignore_known_secrets", [True, False])
@pytest.mark.parametrize(
    "secrets_types", ["only_new_secrets", "only_known_secrets", "mixed_secrets"]
)
def test_ignore_known_secrets(verbose, ignore_known_secrets, secrets_types):
    """
    GIVEN policy breaks
    WHEN generating json output
    THEN if ignore_known_secrets is used, include "known_secret" field for the known policy breaks in the json output
    """
    output_handler = SecretJSONOutputHandler(show_secrets=True, verbose=verbose)

    result: Result = Result(
        StringScannable(
            content=_ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
            url="leak.txt",
            filemode=Filemode.NEW,
        ),
        scan=deepcopy(TWO_POLICY_BREAKS),  # 2 policy breaks
    )

    all_policy_breaks = result.scan.policy_breaks

    known_policy_breaks = []
    new_policy_breaks = all_policy_breaks

    # add known_secret for the secrets that are known, when the option is, the known_secret field is not returned
    if ignore_known_secrets:
        if secrets_types == "only_known_secrets":
            known_policy_breaks = all_policy_breaks
            new_policy_breaks = []
        elif secrets_types == "mixed_secrets":
            # set only first policy break as known
            known_policy_breaks = all_policy_breaks[:1]
            new_policy_breaks = all_policy_breaks[1:]

    for index, policy_break in enumerate(known_policy_breaks):
        policy_break.known_secret = True
        policy_break.incident_url = (
            f"https://dashboard.gitguardian.com/workspace/1/incidents/{index}"
        )

    # call output handler
    output = output_handler._process_scan_impl(
        SecretScanCollection(
            id="outer_scan",
            type="outer_scan",
            results=Results(results=[], errors=[]),
            scans=[
                SecretScanCollection(
                    id="scan",
                    type="test",
                    results=Results(results=[result], errors=[]),
                    optional_header="> This is an example header",
                )
            ],
        )
    )

    incidents = json.loads(output)["scans"][0]["entities_with_incidents"][0][
        "incidents"
    ]
    # We can rely on the policy break type, since in this test there are 2 policy breaks,
    # and they are of different types
    incident_for_policy_break_type = {
        incident["type"]: incident for incident in incidents
    }

    for policy_break in known_policy_breaks:
        assert incident_for_policy_break_type[policy_break.break_type]["known_secret"]
        assert incident_for_policy_break_type[policy_break.break_type][
            "incident_url"
        ].startswith("https://dashboard.gitguardian.com/workspace/1/incidents/")

    for policy_break in new_policy_breaks:
        assert not incident_for_policy_break_type[policy_break.break_type][
            "known_secret"
        ]
        assert not incident_for_policy_break_type[policy_break.break_type][
            "incident_url"
        ]
