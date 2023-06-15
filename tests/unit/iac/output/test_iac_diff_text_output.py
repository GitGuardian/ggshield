import re

from ggshield.iac.output.iac_text_output_handler import IaCTextOutputHandler
from ggshield.iac.collection.iac_diff_scan_collection import IaCDiffScanCollection
from ggshield.iac.iac_scan_models import IaCDiffScanResult, IaCDiffScanEntities

def test_iac_scan_diff_no_vuln_not_verbose():
    """
    GIVEN a response from the GIM api after a iac scan diff
    WHEN verbose mode is not enabled
    THEN output should display version, new incidents and scan summary
    """
    output_handler = IaCTextOutputHandler(False)
    output = output_handler._process_diff_scan_impl(IaCDiffScanCollection(
        id="ID",
        result=IaCDiffScanResult(
            id="ID",
            type="TYPE",
            iac_engine_version="1.0.0",
            entities_with_incidents=IaCDiffScanEntities(
                new=[], unchanged=[], deleted=[]
            )
        )
    ))

    assert_iac_diff_version_displayed(output)
    assert_iac_diff_no_incident_message(output)
    assert_iac_diff_summary_displayed(output)


def test_iac_scan_diff_no_vuln_not_verbose():
    """
    GIVEN a response from the GIM api after a iac scan diff
    WHEN verbose mode is not enabled
    THEN output should display version, new incidents and scan summary
    """
    output_handler = IaCTextOutputHandler(False)
    output = output_handler._process_diff_scan_impl(IaCDiffScanCollection(
        id="ID",
        result=IaCDiffScanResult(
            id="ID",
            type="TYPE",
            iac_engine_version="1.0.0",
            entities_with_incidents=IaCDiffScanEntities(
                new=[], unchanged=[], deleted=[]
            )
        )
    ))

    assert_iac_diff_version_displayed(output)
    assert_iac_diff_summary_displayed(output)

def test_iac_scan_diff_no_vuln_verbose():
    """
    GIVEN a response from the GIM api after a iac scan diff
    WHEN verbose mode is enabled
    THEN output should display version, new incidents, unchanged incidents, deleted incidents, and scan summary
    """
    output_handler = IaCTextOutputHandler(True)
    output = output_handler._process_diff_scan_impl(IaCDiffScanCollection(
        id="ID",
        result=IaCDiffScanResult(
            id="ID",
            type="TYPE",
            iac_engine_version="1.0.0",
            entities_with_incidents=IaCDiffScanEntities(
                new=[], unchanged=[], deleted=[]
            )
        )
    ))

    assert_iac_diff_version_displayed(output)
    assert_iac_diff_no_incident_message(output)
    assert_iac_diff_summary_displayed(output)


def assert_iac_diff_version_displayed(output: str):
    assert re.search(r"iac-engine-version: \d\.\d{1,3}\.\d", output)

def assert_iac_diff_no_incident_message(output: str):
    assert re.search(r"No incidents have been found", output)

def assert_iac_diff_summary_displayed(output: str):
    assert re.search(r"\[-\] \d+ incidents? deleted", output)
    assert re.search(r"\[~\] \d+ incidents? remaining", output)
    assert re.search(r"\[\+\] \d+ new incidents? detected", output)