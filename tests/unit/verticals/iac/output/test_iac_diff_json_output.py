import json

from pygitguardian.iac_models import (
    IaCDiffScanEntities,
    IaCDiffScanResult,
    IaCFileResult,
    IaCVulnerability,
)

from ggshield.verticals.iac.collection.iac_diff_scan_collection import (
    IaCDiffScanCollection,
)
from ggshield.verticals.iac.output import IaCJSONOutputHandler


def file_result_factory(filename: str, incidents: int = 1) -> IaCFileResult:
    return IaCFileResult(
        filename=filename,
        incidents=[
            IaCVulnerability(
                component="COMPONENT",
                description="DESCRIPTION",
                documentation_url="DOCUMENTATION_URL",
                line_start=0,
                line_end=0,
                policy="POLICY",
                policy_id="POLICY_ID",
                severity="SEVERITY",
            )
            for _ in range(incidents)
        ],
    )


def test_iac_scan_diff_one_new():
    """
    GIVEN a iac scan diff collection
    WHEN only one new incident has been found
    THEN ensure json format is correct
    """
    output_handler = IaCJSONOutputHandler(True)
    raw_json = output_handler._process_diff_scan_impl(
        IaCDiffScanCollection(
            id="id",
            result=IaCDiffScanResult(
                id="id",
                type="type",
                iac_engine_version="",
                entities_with_incidents=IaCDiffScanEntities(
                    new=[
                        file_result_factory("/path/to/first/file.tf"),
                    ],
                    unchanged=[],
                    deleted=[],
                ),
            ),
        )
    )
    parsed_json = json.loads(raw_json)
    assert parsed_json == {
        "id": "id",
        "type": "type",
        "iac_engine_version": "",
        "entities_with_incidents": {
            "unchanged": [],
            "new": [
                {
                    "filename": "/path/to/first/file.tf",
                    "incidents": [
                        {
                            "policy": "POLICY",
                            "policy_id": "POLICY_ID",
                            "line_end": 0,
                            "line_start": 0,
                            "description": "DESCRIPTION",
                            "documentation_url": "DOCUMENTATION_URL",
                            "component": "COMPONENT",
                            "severity": "SEVERITY",
                        }
                    ],
                    "total_incidents": 1,
                }
            ],
            "deleted": [],
        },
    }


def test_iac_scan_diff_several_new():
    """
    GIVEN a iac scan diff collection
    WHEN several new incident have been found
    THEN ensure json format is correct
    """
    output_handler = IaCJSONOutputHandler(True)
    raw_json = output_handler._process_diff_scan_impl(
        IaCDiffScanCollection(
            id="id",
            result=IaCDiffScanResult(
                id="id",
                type="type",
                iac_engine_version="",
                entities_with_incidents=IaCDiffScanEntities(
                    new=[
                        file_result_factory("/path/to/first/file.tf"),
                        file_result_factory("/path/to/second/file.tf"),
                        file_result_factory("/path/to/third/file.tf"),
                    ],
                    unchanged=[],
                    deleted=[],
                ),
            ),
        )
    )
    parsed_json = json.loads(raw_json)

    assert parsed_json == {
        "id": "id",
        "type": "type",
        "iac_engine_version": "",
        "entities_with_incidents": {
            "unchanged": [],
            "new": [
                {
                    "filename": "/path/to/first/file.tf",
                    "incidents": [
                        {
                            "policy": "POLICY",
                            "policy_id": "POLICY_ID",
                            "line_end": 0,
                            "line_start": 0,
                            "description": "DESCRIPTION",
                            "documentation_url": "DOCUMENTATION_URL",
                            "component": "COMPONENT",
                            "severity": "SEVERITY",
                        }
                    ],
                    "total_incidents": 1,
                },
                {
                    "filename": "/path/to/second/file.tf",
                    "incidents": [
                        {
                            "policy": "POLICY",
                            "policy_id": "POLICY_ID",
                            "line_end": 0,
                            "line_start": 0,
                            "description": "DESCRIPTION",
                            "documentation_url": "DOCUMENTATION_URL",
                            "component": "COMPONENT",
                            "severity": "SEVERITY",
                        }
                    ],
                    "total_incidents": 1,
                },
                {
                    "filename": "/path/to/third/file.tf",
                    "incidents": [
                        {
                            "policy": "POLICY",
                            "policy_id": "POLICY_ID",
                            "line_end": 0,
                            "line_start": 0,
                            "description": "DESCRIPTION",
                            "documentation_url": "DOCUMENTATION_URL",
                            "component": "COMPONENT",
                            "severity": "SEVERITY",
                        }
                    ],
                    "total_incidents": 1,
                },
            ],
            "deleted": [],
        },
    }


def test_iac_scan_diff_several_new_on_same_file():
    """
    GIVEN a iac scan diff collection
    WHEN several new incidents on same file have been found
    THEN ensure json format is correct
    """
    output_handler = IaCJSONOutputHandler(True)
    raw_json = output_handler._process_diff_scan_impl(
        IaCDiffScanCollection(
            id="id",
            result=IaCDiffScanResult(
                id="id",
                type="type",
                iac_engine_version="",
                entities_with_incidents=IaCDiffScanEntities(
                    new=[
                        file_result_factory("/path/to/first/file.tf", incidents=3),
                    ],
                    unchanged=[],
                    deleted=[],
                ),
            ),
        )
    )
    parsed_json = json.loads(raw_json)

    assert parsed_json == {
        "id": "id",
        "type": "type",
        "iac_engine_version": "",
        "entities_with_incidents": {
            "unchanged": [],
            "new": [
                {
                    "filename": "/path/to/first/file.tf",
                    "incidents": [
                        {
                            "policy": "POLICY",
                            "policy_id": "POLICY_ID",
                            "line_end": 0,
                            "line_start": 0,
                            "description": "DESCRIPTION",
                            "documentation_url": "DOCUMENTATION_URL",
                            "component": "COMPONENT",
                            "severity": "SEVERITY",
                        },
                        {
                            "policy": "POLICY",
                            "policy_id": "POLICY_ID",
                            "line_end": 0,
                            "line_start": 0,
                            "description": "DESCRIPTION",
                            "documentation_url": "DOCUMENTATION_URL",
                            "component": "COMPONENT",
                            "severity": "SEVERITY",
                        },
                        {
                            "policy": "POLICY",
                            "policy_id": "POLICY_ID",
                            "line_end": 0,
                            "line_start": 0,
                            "description": "DESCRIPTION",
                            "documentation_url": "DOCUMENTATION_URL",
                            "component": "COMPONENT",
                            "severity": "SEVERITY",
                        },
                    ],
                    "total_incidents": 3,
                },
            ],
            "deleted": [],
        },
    }


def test_iac_scan_diff_one_persisting():
    """
    GIVEN a iac scan diff collection
    WHEN only one persisting incident has been found
    THEN ensure json format is correct
    """
    output_handler = IaCJSONOutputHandler(True)
    raw_json = output_handler._process_diff_scan_impl(
        IaCDiffScanCollection(
            id="id",
            result=IaCDiffScanResult(
                id="id",
                type="type",
                iac_engine_version="",
                entities_with_incidents=IaCDiffScanEntities(
                    new=[],
                    unchanged=[
                        file_result_factory("/path/to/first/file.tf"),
                    ],
                    deleted=[],
                ),
            ),
        )
    )
    parsed_json = json.loads(raw_json)

    assert parsed_json == {
        "id": "id",
        "type": "type",
        "iac_engine_version": "",
        "entities_with_incidents": {
            "unchanged": [
                {
                    "filename": "/path/to/first/file.tf",
                    "incidents": [
                        {
                            "policy": "POLICY",
                            "policy_id": "POLICY_ID",
                            "line_end": 0,
                            "line_start": 0,
                            "description": "DESCRIPTION",
                            "documentation_url": "DOCUMENTATION_URL",
                            "component": "COMPONENT",
                            "severity": "SEVERITY",
                        }
                    ],
                    "total_incidents": 1,
                }
            ],
            "new": [],
            "deleted": [],
        },
    }


def test_iac_scan_diff_one_removed():
    """
    GIVEN a iac scan diff collection
    WHEN only one removed incident has been found
    THEN ensure json format is correct
    """
    output_handler = IaCJSONOutputHandler(True)
    raw_json = output_handler._process_diff_scan_impl(
        IaCDiffScanCollection(
            id="id",
            result=IaCDiffScanResult(
                id="id",
                type="type",
                iac_engine_version="",
                entities_with_incidents=IaCDiffScanEntities(
                    new=[],
                    unchanged=[],
                    deleted=[
                        file_result_factory("/path/to/first/file.tf"),
                    ],
                ),
            ),
        )
    )
    parsed_json = json.loads(raw_json)

    assert parsed_json == {
        "id": "id",
        "type": "type",
        "iac_engine_version": "",
        "entities_with_incidents": {
            "unchanged": [],
            "new": [],
            "deleted": [
                {
                    "filename": "/path/to/first/file.tf",
                    "incidents": [
                        {
                            "policy": "POLICY",
                            "policy_id": "POLICY_ID",
                            "line_end": 0,
                            "line_start": 0,
                            "description": "DESCRIPTION",
                            "documentation_url": "DOCUMENTATION_URL",
                            "component": "COMPONENT",
                            "severity": "SEVERITY",
                        }
                    ],
                    "total_incidents": 1,
                }
            ],
        },
    }
