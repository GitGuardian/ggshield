import json
import operator
from collections import namedtuple
from copy import deepcopy
from typing import Any, Dict, List, Optional, TypedDict
from unittest.mock import Mock

import pytest
from pygitguardian import GGClient
from pygitguardian.models import SecretIncident
from pytest_voluptuous import Partial, S
from voluptuous import Optional as VOptional
from voluptuous import Required, validators

from ggshield.core.config.user_config import SecretConfig
from ggshield.core.scan import Commit, ScanContext, ScanMode, StringScannable
from ggshield.core.scan.file import File
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
from ggshield.verticals.secret.secret_scan_collection import (
    IgnoreKind,
    IgnoreReason,
    group_secrets_by_ignore_sha,
)
from tests.factories import PolicyBreakFactory, ScannableFactory, ScanResultFactory
from tests.unit.conftest import (
    _MULTILINE_SECRET_FILE,
    _MULTIPLE_SECRETS_PATCH,
    _NO_SECRET_PATCH,
    _ONE_LINE_AND_MULTILINE_FILE,
    _ONE_LINE_AND_MULTILINE_PATCH,
    _ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
    _SINGLE_ADD_PATCH,
    _SINGLE_DELETE_PATCH,
    _SINGLE_LINE_SECRET_FILE,
    _SINGLE_MOVE_PATCH,
    SECRET_INCIDENT_MOCK,
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
                            "FILE",
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
                                    "detector": str,
                                    "policy": str,
                                    "total_occurrences": validators.All(int, min=1),
                                    Required("incident_url"): validators.Match(
                                        r"^($|https://)"
                                    ),
                                    "occurrences": validators.All(
                                        [
                                            {
                                                "match": str,
                                                "type": str,
                                                "line_start": int,
                                                "line_end": int,
                                                "index_start": int,
                                                "index_end": int,
                                                "pre_line_start": VOptional(int),
                                                "pre_line_end": VOptional(int),
                                                "post_line_start": VOptional(int),
                                                "post_line_end": VOptional(int),
                                            }
                                        ],
                                        validators.Length(min=1),
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
    index_start: int
    index_end: int
    pre_line_start: Optional[int]
    pre_line_end: Optional[int]
    post_line_start: Optional[int]
    post_line_end: Optional[int]


MATCH_INDICES: Dict[str, List[ExpectedIndicesDict]] = {
    _MULTIPLE_SECRETS_PATCH: [
        {
            "line_start": 2,
            "line_end": 2,
            "index_start": 79,
            "index_end": 89,
            "pre_line_start": None,
            "pre_line_end": None,
            "post_line_start": 2,
            "post_line_end": 2,
        },
        {
            "line_start": 2,
            "line_end": 2,
            "index_start": 116,
            "index_end": 120,
            "pre_line_start": None,
            "pre_line_end": None,
            "post_line_start": 2,
            "post_line_end": 2,
        },
        {
            "line_start": 2,
            "line_end": 2,
            "index_start": 139,
            "index_end": 143,
            "pre_line_start": None,
            "pre_line_end": None,
            "post_line_start": 2,
            "post_line_end": 2,
        },
        {
            "line_start": 2,
            "line_end": 2,
            "index_start": 174,
            "index_end": 184,
            "pre_line_start": None,
            "pre_line_end": None,
            "post_line_start": 2,
            "post_line_end": 2,
        },
    ],
    UNCHECKED_SECRET_PATCH: [
        {
            "line_start": 2,
            "line_end": 2,
            "index_start": 11,
            "index_end": 280,
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
            "index_start": 11,
            "index_end": 28,
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
            "index_start": 69,
            "index_end": 30,
            "pre_line_start": None,
            "pre_line_end": None,
            "post_line_start": 1,
            "post_line_end": 9,
        },
        {
            "line_start": 9,
            "line_end": 9,
            "index_start": 38,
            "index_end": 107,
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
            "index_start": 11,
            "index_end": 80,
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
            "index_start": 11,
            "index_end": 80,
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
            "index_start": 11,
            "index_end": 80,
            "pre_line_start": 150,
            "pre_line_end": 150,
            "post_line_start": 151,
            "post_line_end": 151,
        }
    ],
    _MULTILINE_SECRET_FILE: [
        {
            "line_start": 1,
            "line_end": 9,
            "index_start": 0,
            "index_end": 29,
            "pre_line_start": None,
            "pre_line_end": None,
            "post_line_start": None,
            "post_line_end": None,
        },
    ],
    _SINGLE_LINE_SECRET_FILE: [
        {
            "line_start": 1,
            "line_end": 1,
            "index_start": 10,
            "index_end": 279,
            "pre_line_start": None,
            "pre_line_end": None,
            "post_line_start": None,
            "post_line_end": None,
        }
    ],
    _ONE_LINE_AND_MULTILINE_FILE: [
        {
            "line_start": 2,
            "line_end": 10,
            "index_start": 68,
            "index_end": 29,
            "pre_line_start": None,
            "pre_line_end": None,
            "post_line_start": None,
            "post_line_end": None,
        },
        {
            "line_start": 10,
            "line_end": 10,
            "index_start": 37,
            "index_end": 106,
            "pre_line_start": None,
            "pre_line_end": None,
            "post_line_start": None,
            "post_line_end": None,
        },
    ],
}


def create_occurrence_indices_dict(occurrence: Dict[str, Any]) -> ExpectedIndicesDict:
    return {k: occurrence.get(k) for k in ExpectedIndicesDict.__annotations__.keys()}


def check_occurrences_indices(
    occurrences: List[Dict[str, Any]], match_indices_list: List[ExpectedIndicesDict]
) -> None:
    """
    Check `occurrences` contains the expected indices for patch `patch`.
    """
    line_start_getter = operator.itemgetter("line_start")

    occurrences_indices_list = [create_occurrence_indices_dict(x) for x in occurrences]
    assert sorted(occurrences_indices_list, key=line_start_getter) == sorted(
        match_indices_list, key=line_start_getter
    )


@pytest.mark.parametrize(
    "name,input,expected_exit_code,is_patch",
    [
        ("multiple_secrets", _MULTIPLE_SECRETS_PATCH, 1, True),
        ("simple_secret", UNCHECKED_SECRET_PATCH, 1, True),
        ("test_scan_file_secret_with_validity", VALID_SECRET_PATCH, 1, True),
        ("one_line_and_multiline_patch", _ONE_LINE_AND_MULTILINE_PATCH, 1, True),
        ("no_secret", _NO_SECRET_PATCH, 0, True),
        ("single_add", _SINGLE_ADD_PATCH, 1, True),
        (
            "single_delete",
            _SINGLE_DELETE_PATCH,
            0,
            True,
        ),  # no issue because secret is removed
        (
            "single_move",
            _SINGLE_MOVE_PATCH,
            0,
            True,
        ),  # no issue because secret is not added
        ("multiline_secret", _MULTILINE_SECRET_FILE, 1, False),
        ("single_line_secret", _SINGLE_LINE_SECRET_FILE, 1, False),
        ("one_line_and_multiline_secrets", _ONE_LINE_AND_MULTILINE_FILE, 1, False),
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
        "_MULTILINE_SECRET_FILE",
        "_SINGLE_LINE_SECRET_FILE",
        "_ONE_LINE_AND_MULTILINE_FILE",
    ],
)
def test_json_output_for_patch(
    client, cache, name, input, expected_exit_code, is_patch, tmp_path
):
    if is_patch:
        commit = Commit.from_patch(input)
        scannables = commit.get_files()
    else:
        test_file = tmp_path / "file"
        with open(test_file, "w", newline="\n") as f:
            f.write(input)
        scannables = [File(path=test_file)]

    secret_config = SecretConfig(
        show_secrets=False,
    )
    handler = SecretJSONOutputHandler(verbose=True, secret_config=secret_config)

    with my_vcr.use_cassette(name):
        scanner = SecretScanner(
            client=client,
            cache=cache,
            scan_context=ScanContext(
                scan_mode=ScanMode.PATH,
                command_path="external",
            ),
            secret_config=secret_config,
        )
        results = scanner.scan(scannables, scanner_ui=Mock())

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
            check_occurrences_indices(occurrences, MATCH_INDICES[input])

        # all ignore sha should be in the output
        assert all(
            ignore_sha in json_flat_results
            for result in results.results
            for ignore_sha in group_secrets_by_ignore_sha(result.secrets)
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

    secret_config = SecretConfig(
        show_secrets=True,
    )
    output_handler = SecretJSONOutputHandler(
        verbose=verbose, secret_config=secret_config
    )

    result: Result = Result.from_scan_result(
        StringScannable(
            content=_ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
            url="leak.txt",
            filemode=Filemode.NEW,
        ),
        scan_result=deepcopy(TWO_POLICY_BREAKS),
        secret_config=SecretConfig(),  # 2 policy breaks
    )

    all_secrets = result.secrets

    known_secrets = []
    new_secrets = all_secrets

    # add known_secret for the secrets that are known, when the option is, the known_secret field is not returned
    if ignore_known_secrets:
        if secrets_types == "only_known_secrets":
            known_secrets = all_secrets
            new_secrets = []
        elif secrets_types == "mixed_secrets":
            # set only first policy break as known
            known_secrets = all_secrets[:1]
            new_secrets = all_secrets[1:]

    for index, secret in enumerate(known_secrets):
        secret.known_secret = True
        secret.incident_url = (
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
    incident_for_secret_type = {incident["type"]: incident for incident in incidents}

    for secret in known_secrets:
        assert incident_for_secret_type[secret.detector_display_name]["known_secret"]
        assert incident_for_secret_type[secret.detector_display_name][
            "incident_url"
        ].startswith("https://dashboard.gitguardian.com/workspace/1/incidents/")

    for secret in new_secrets:
        assert not incident_for_secret_type[secret.detector_display_name][
            "known_secret"
        ]
        assert not incident_for_secret_type[secret.detector_display_name][
            "incident_url"
        ]


@pytest.mark.parametrize("with_incident_details", [True, False])
@pytest.mark.parametrize(
    "secrets_types", ["only_new_secrets", "only_known_secrets", "mixed_secrets"]
)
def test_with_incident_details(
    with_incident_details,
    secrets_types,
):
    """
    GIVEN policy breaks
    WHEN generating json output
    THEN if ignore_known_secrets is used, include "known_secret" field for the known policy breaks in the json output
    """
    client_mock = Mock(spec=GGClient)
    client_mock.retrieve_secret_incident.return_value = SECRET_INCIDENT_MOCK
    secret_config = SecretConfig(
        show_secrets=False, with_incident_details=with_incident_details
    )
    output_handler = SecretJSONOutputHandler(
        verbose=True, secret_config=secret_config, client=client_mock
    )

    result: Result = Result.from_scan_result(
        StringScannable(
            content=_ONE_LINE_AND_MULTILINE_PATCH_CONTENT,
            url="leak.txt",
            filemode=Filemode.NEW,
        ),
        scan_result=deepcopy(TWO_POLICY_BREAKS),
        secret_config=SecretConfig(),  # 2 policy breaks
    )

    all_secrets = result.secrets

    known_secrets = []

    if with_incident_details:
        if secrets_types == "only_known_secrets":
            known_secrets = all_secrets
        elif secrets_types == "mixed_secrets":
            # set only first policy break as known
            known_secrets = all_secrets[:1]

    for index, secret in enumerate(known_secrets):
        secret.known_secret = True
        secret.incident_url = (
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

    if with_incident_details:
        assert client_mock.retrieve_secret_incident.call_count == len(known_secrets)
        for incident in incidents:
            if incident["known_secret"]:
                assert incident["incident_details"]
                SecretIncident(**incident["incident_details"])
            else:
                assert "incident_details" not in incident
    else:
        assert client_mock.retrieve_secret_incident.call_count == 0


@pytest.mark.parametrize(
    ("ignore_reason", "expected_output"),
    (
        (None, None),
        (
            IgnoreReason(kind=IgnoreKind.IGNORED_MATCH),
            {
                "kind": IgnoreKind.IGNORED_MATCH.name.lower(),
                "detail": None,
            },
        ),
        (
            IgnoreReason(kind=IgnoreKind.BACKEND_EXCLUDED, detail="some detail"),
            {
                "kind": IgnoreKind.BACKEND_EXCLUDED.name.lower(),
                "detail": "some detail",
            },
        ),
    ),
)
def test_ignore_reason(ignore_reason, expected_output):
    """
    GIVEN an result
    WHEN it is passed to the json output handler
    THEN the ignore_reason field is as expected
    """

    secret_config = SecretConfig()
    scannable = ScannableFactory()
    policy_break = PolicyBreakFactory(content=scannable.content)
    result = Result.from_scan_result(
        scannable, ScanResultFactory(policy_breaks=[policy_break]), secret_config
    )
    result.secrets[0].ignore_reason = ignore_reason

    output_handler = SecretJSONOutputHandler(secret_config=secret_config, verbose=False)

    output = output_handler._process_scan_impl(
        SecretScanCollection(
            id="scan",
            type="scan",
            results=Results(results=[result], errors=[]),
        )
    )

    parsed_incidents = json.loads(output)["entities_with_incidents"][0]["incidents"]
    assert parsed_incidents[0]["ignore_reason"] == expected_output


@pytest.mark.parametrize(
    "is_vaulted",
    (True, False),
)
def test_vaulted_secret(is_vaulted: bool):
    """
    GIVEN an result
    WHEN it is passed to the json output handler
    THEN the vaulted_secret field is as expected
    """

    secret_config = SecretConfig()
    scannable = ScannableFactory()
    policy_break = PolicyBreakFactory(content=scannable.content, is_vaulted=is_vaulted)
    result = Result.from_scan_result(
        scannable, ScanResultFactory(policy_breaks=[policy_break]), secret_config
    )

    output_handler = SecretJSONOutputHandler(secret_config=secret_config, verbose=False)

    output = output_handler._process_scan_impl(
        SecretScanCollection(
            id="scan",
            type="scan",
            results=Results(results=[result], errors=[]),
        )
    )

    parsed_incidents = json.loads(output)["entities_with_incidents"][0]["incidents"]
    assert parsed_incidents[0]["secret_vaulted"] == is_vaulted


@pytest.mark.parametrize(
    "vault_type,vault_name,vault_path,vault_path_count,expected_fields",
    [
        (None, None, None, None, {}),
        (
            "HashiCorp Vault",
            "vault.example.org",
            "/path/to/secret",
            1,
            {
                "vault_type": "HashiCorp Vault",
                "vault_name": "vault.example.org",
                "vault_path": "/path/to/secret",
                "vault_path_count": 1,
            },
        ),
        (
            "HashiCorp Vault",
            "vault.example.org",
            "/path/to/secret",
            4,
            {
                "vault_type": "HashiCorp Vault",
                "vault_name": "vault.example.org",
                "vault_path": "/path/to/secret",
                "vault_path_count": 4,
            },
        ),
        (
            "HashiCorp Vault",
            "vault.example.org",
            "/path/to/secret",
            1,
            {
                "vault_type": "HashiCorp Vault",
                "vault_name": "vault.example.org",
                "vault_path": "/path/to/secret",
            },
        ),
    ],
)
def test_vault_path_in_json_output(
    vault_type: Optional[str],
    vault_name: Optional[str],
    vault_path: Optional[str],
    vault_path_count: Optional[int],
    expected_fields: Dict[str, Any],
):
    """
    GIVEN a secret with vault information
    WHEN it is passed to the json output handler
    THEN the vault_type, vault_name, vault_path and vault_path_count fields are included as expected
    """

    secret_config = SecretConfig()
    scannable = ScannableFactory()
    policy_break = PolicyBreakFactory(
        content=scannable.content,
        is_vaulted=vault_type is not None,
        vault_type=vault_type,
        vault_name=vault_name,
        vault_path=vault_path,
        vault_path_count=vault_path_count,
    )
    result = Result.from_scan_result(
        scannable, ScanResultFactory(policy_breaks=[policy_break]), secret_config
    )

    output_handler = SecretJSONOutputHandler(secret_config=secret_config, verbose=False)

    output = output_handler._process_scan_impl(
        SecretScanCollection(
            id="scan",
            type="scan",
            results=Results(results=[result], errors=[]),
        )
    )

    parsed_incidents = json.loads(output)["entities_with_incidents"][0]["incidents"]
    incident = parsed_incidents[0]

    for field, expected_value in expected_fields.items():
        assert incident.get(field) == expected_value

    # Check that fields are not present when vault information is None
    if vault_type is None:
        assert "vault_type" not in incident
        assert "vault_name" not in incident
        assert "vault_path" not in incident
        assert "vault_path_count" not in incident
