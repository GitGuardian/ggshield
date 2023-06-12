from pygitguardian.iac_models import IaCFileResult, IaCScanResult, IaCVulnerability

from ggshield.iac.collection.iac_diff_scan_collection import IaCDiffScanCollection
from ggshield.iac.collection.iac_path_scan_collection import IaCPathScanCollection
from ggshield.iac.collection.iac_scan_collection import CollectionType
from ggshield.iac.iac_scan_models import IaCDiffScanEntities, IaCDiffScanResult


def test_iac_path_scan_collection_type() -> None:
    """
    GIVEN an IaC path scan collection
    WHEN accessing its type
    THEN the type is CollectionType.PathScan
    """
    collection = IaCPathScanCollection("0", IaCScanResult("0", "path_scan", "", []))
    assert collection.type == CollectionType.PathScan


def test_iac_diff_scan_collection_type() -> None:
    """
    GIVEN an IaC diff scan collection
    WHEN accessing its type
    THEN the type is CollectionType.DiffScan
    """
    collection = IaCDiffScanCollection("0", IaCDiffScanResult("0", "diff_scan", "", []))
    assert collection.type == CollectionType.DiffScan


def test_iac_path_scan_collection_has_no_results() -> None:
    """
    GIVEN an IaC scan collection with no result
    THEN has_results returns False
    """
    collection = IaCPathScanCollection("0", IaCScanResult("0", "path_scan", "", []))
    assert not collection.has_results

    collection = IaCPathScanCollection("0", IaCDiffScanResult("0", "diffscan", "", []))
    assert not collection.has_results


def test_iac_path_scan_collection_has_results() -> None:
    """
    GIVEN an IaC scan collection with some results
    THEN has_results returns True
    """
    file_result = IaCFileResult(
        "a.py", [IaCVulnerability("", "", 0, 0, "", "", "", "")]
    )

    collection = IaCPathScanCollection(
        "0", IaCScanResult("0", "path_scan", "", [file_result])
    )
    assert collection.has_results

    collection = IaCPathScanCollection(
        "0",
        IaCDiffScanResult(
            "0",
            "diffscan",
            "",
            [
                IaCDiffScanEntities(
                    unchanged=file_result, deleted=file_result, new=file_result
                )
            ],
        ),
    )
    assert collection.has_results
