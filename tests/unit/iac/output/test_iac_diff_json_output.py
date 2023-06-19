import json

from pygitguardian.iac_models import IaCFileResult, IaCVulnerability

from ggshield.iac.collection.iac_diff_scan_collection import IaCDiffScanCollection
from ggshield.iac.iac_scan_models import IaCDiffScanEntities, IaCDiffScanResult
from ggshield.iac.output import IaCJSONOutputHandler


def test_iac_scan_diff():
    # run
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
                        IaCFileResult(
                            filename="/path/to/file.tf",
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
                            ],
                        )
                    ],
                    unchanged=[],
                    deleted=[],
                ),
            ),
        )
    )
    parsed_json = json.loads(raw_json)

    assert parsed_json == {
        "added_vulns": [
            {
                "filename": "/path/to/file.tf",
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
                "total_incidents": 0,
            }
        ],
        "persisting_vulns": [],
        "removed_vulns": [],
    }
