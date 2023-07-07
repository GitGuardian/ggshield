import re

from pygitguardian.iac_models import (
    IaCDiffScanEntities,
    IaCDiffScanResult,
    IaCFileResult,
    IaCVulnerability,
)

from ggshield.iac.collection.iac_diff_scan_collection import IaCDiffScanCollection
from ggshield.iac.output.iac_text_output_handler import IaCTextOutputHandler


def test_iac_scan_diff_no_vuln_not_verbose():
    """
    GIVEN a response from the GIM api after a iac scan diff
    WHEN verbose mode is not enabled
    THEN output should display version, new incidents and scan summary
    """
    output_handler = IaCTextOutputHandler(False)
    output = output_handler._process_diff_scan_impl(
        IaCDiffScanCollection(
            id="ID",
            result=IaCDiffScanResult(
                id="ID",
                type="TYPE",
                iac_engine_version="1.0.0",
                entities_with_incidents=IaCDiffScanEntities(
                    new=[], unchanged=[], deleted=[]
                ),
            ),
        )
    )

    assert_iac_diff_version_displayed(output)
    assert_iac_diff_no_new_incident_message(output)
    assert_iac_diff_summary_displayed(output)


def test_iac_scan_diff_vuln_not_verbose():
    """
    GIVEN a response from the GIM api after a iac scan diff
    WHEN verbose mode is not enabled
    THEN output should display version, new incidents and scan summary
    """
    output_handler = IaCTextOutputHandler(False)
    output = output_handler._process_diff_scan_impl(
        IaCDiffScanCollection(
            id="ID",
            result=IaCDiffScanResult(
                id="ID",
                type="TYPE",
                iac_engine_version="1.0.0",
                entities_with_incidents=IaCDiffScanEntities(
                    new=[
                        IaCFileResult(
                            filename="FILENAME.tf",
                            incidents=[
                                IaCVulnerability(
                                    policy="POLICY",
                                    policy_id="POLICY_ID",
                                    line_start=0,
                                    line_end=1,
                                    description="DESCRIPTION",
                                    component="COMPONENT",
                                    severity="SEVERITY",
                                    documentation_url="DOCUMENT_URL",
                                )
                            ],
                        )
                    ],
                    unchanged=[
                        IaCFileResult(
                            filename="FILENAME.tf",
                            incidents=[
                                IaCVulnerability(
                                    policy="POLICY",
                                    policy_id="POLICY_ID",
                                    line_start=0,
                                    line_end=1,
                                    description="DESCRIPTION",
                                    component="COMPONENT",
                                    severity="SEVERITY",
                                    documentation_url="DOCUMENT_URL",
                                )
                            ],
                        )
                    ],
                    deleted=[
                        IaCFileResult(
                            filename="FILENAME.tf",
                            incidents=[
                                IaCVulnerability(
                                    policy="POLICY",
                                    policy_id="POLICY_ID",
                                    line_start=0,
                                    line_end=1,
                                    description="DESCRIPTION",
                                    component="COMPONENT",
                                    severity="SEVERITY",
                                    documentation_url="DOCUMENT_URL",
                                )
                            ],
                        )
                    ],
                ),
            ),
        )
    )

    assert_iac_diff_version_displayed(output)
    assert re.search(r"FILENAME\.tf.*1 new incident detected", output)
    assert_iac_diff_summary_displayed(output, new=1, unchanged=1, deleted=1)


def test_iac_scan_diff_no_vuln_verbose():
    """
    GIVEN a response from the GIM api after a iac scan diff
    WHEN verbose mode is enabled
    THEN output should display version, new incidents, unchanged incidents, deleted incidents, and scan summary
    """
    output_handler = IaCTextOutputHandler(True)
    output = output_handler._process_diff_scan_impl(
        IaCDiffScanCollection(
            id="ID",
            result=IaCDiffScanResult(
                id="ID",
                type="TYPE",
                iac_engine_version="1.0.0",
                entities_with_incidents=IaCDiffScanEntities(
                    new=[], unchanged=[], deleted=[]
                ),
            ),
        )
    )

    assert_iac_diff_version_displayed(output)
    assert_iac_diff_no_incident_message(output)
    assert_iac_diff_summary_displayed(output)


def test_iac_scan_diff_vuln_verbose():
    """
    GIVEN a response from the GIM api after a iac scan diff
    WHEN verbose mode is enabled
    THEN output should display version, new incidents, unchanged incidents, deleted incidents, and scan summary
    """
    output_handler = IaCTextOutputHandler(True)
    output = output_handler._process_diff_scan_impl(
        IaCDiffScanCollection(
            id="ID",
            result=IaCDiffScanResult(
                id="ID",
                type="TYPE",
                iac_engine_version="1.0.0",
                entities_with_incidents=IaCDiffScanEntities(
                    new=[
                        IaCFileResult(
                            filename="FILENAME.tf",
                            incidents=[
                                IaCVulnerability(
                                    policy="POLICY",
                                    policy_id="POLICY_ID",
                                    line_start=0,
                                    line_end=1,
                                    description="DESCRIPTION",
                                    component="COMPONENT",
                                    severity="SEVERITY",
                                    documentation_url="DOCUMENT_URL",
                                )
                            ],
                        )
                    ],
                    unchanged=[
                        IaCFileResult(
                            filename="FILENAME.tf",
                            incidents=[
                                IaCVulnerability(
                                    policy="POLICY",
                                    policy_id="POLICY_ID",
                                    line_start=0,
                                    line_end=1,
                                    description="DESCRIPTION",
                                    component="COMPONENT",
                                    severity="SEVERITY",
                                    documentation_url="DOCUMENT_URL",
                                )
                            ],
                        )
                    ],
                    deleted=[
                        IaCFileResult(
                            filename="FILENAME.tf",
                            incidents=[
                                IaCVulnerability(
                                    policy="POLICY",
                                    policy_id="POLICY_ID",
                                    line_start=0,
                                    line_end=1,
                                    description="DESCRIPTION",
                                    component="COMPONENT",
                                    severity="SEVERITY",
                                    documentation_url="DOCUMENT_URL",
                                )
                            ],
                        )
                    ],
                ),
            ),
        )
    )

    assert_iac_diff_version_displayed(output)
    assert re.search(r"FILENAME\.tf.*1 new incident detected", output)
    assert_iac_diff_summary_displayed(output, new=1, unchanged=1, deleted=1)


def assert_iac_diff_version_displayed(output: str):
    assert re.search(r"iac-engine-version: \d\.\d{1,3}\.\d", output)


def assert_iac_diff_no_incident_message(output: str):
    assert re.search(r"No incidents have been found", output)


def assert_iac_diff_no_new_incident_message(output: str):
    assert re.search(r"No new incidents have been found", output)


def assert_iac_diff_summary_displayed(output: str, new=0, unchanged=0, deleted=0):
    assert re.search(r"\[-\] " + str(deleted) + " incidents? deleted", output)
    assert re.search(r"\[~\] " + str(unchanged) + " incidents? remaining", output)
    assert re.search(r"\[\+\] " + str(new) + " new incidents? detected", output)
