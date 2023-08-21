import pytest
from pygitguardian.iac_models import (
    IaCDiffScanEntities,
    IaCDiffScanResult,
    IaCFileResult,
    IaCScanResult,
    IaCVulnerability,
)

from ggshield.verticals.iac.collection.iac_diff_scan_collection import (
    IaCDiffScanCollection,
)
from ggshield.verticals.iac.collection.iac_path_scan_collection import (
    IaCPathScanCollection,
)
from ggshield.verticals.iac.collection.iac_scan_collection import (
    CollectionType,
    IaCScanCollection,
)


def _generate_empty_path_collection() -> IaCPathScanCollection:
    return IaCPathScanCollection(
        "3ac2985e-dcf9-49ff-92fb-943548268de8",
        IaCScanResult(
            id="3ac2985e-dcf9-49ff-92fb-943548268de8",
            type="path_scan",
            iac_engine_version="1.8.0",
            entities_with_incidents=[],
        ),
    )


def _generate_empty_diff_collection() -> IaCDiffScanCollection:
    return IaCDiffScanCollection(
        "3ac2985e-dcf9-49ff-92fb-943548268de8",
        IaCDiffScanResult(
            id="3ac2985e-dcf9-49ff-92fb-943548268de8",
            type="diff_scan",
            iac_engine_version="1.8.0",
            entities_with_incidents=IaCDiffScanEntities(
                unchanged=[], deleted=[], new=[]
            ),
        ),
    )


def _generate_file_result_with_vulnerability() -> IaCFileResult:
    return IaCFileResult(
        "a.py",
        [
            IaCVulnerability(
                policy="Leaving public access open exposes your service to the internet",
                policy_id="GG_IAC_0024",
                line_end=35,
                line_start=1,
                description="The API server of an AKS cluster [...]",
                documentation_url="https://docs.gitguardian.com/iac-scanning/policies/GG_IAC_0024",
                component="azurerm_kubernetes_cluster.k8s_cluster",
                severity="HIGH",
            )
        ],
    )


@pytest.mark.parametrize(
    "collection,expected_type",
    [
        (_generate_empty_path_collection(), CollectionType.PathScan),
        (_generate_empty_diff_collection(), CollectionType.DiffScan),
    ],
)
def test_iac_path_scan_collection_type(
    collection: IaCScanCollection, expected_type: CollectionType
) -> None:
    """
    GIVEN an IaC scan collection
    THEN the type is either 'path_scan' or 'diff_scan'
    """
    assert collection.type == expected_type


@pytest.mark.parametrize(
    "collection",
    [
        _generate_empty_path_collection(),
        _generate_empty_diff_collection(),
    ],
)
def test_iac_scan_collection_has_no_results(collection: IaCScanCollection) -> None:
    """
    GIVEN an IaC scan collection with no result
    THEN has_results returns False
    """
    assert not collection.has_results


def test_iac_path_scan_collection_has_results() -> None:
    """
    GIVEN an IaC path scan collection with some results
    THEN has_results returns True
    """

    collection = IaCPathScanCollection(
        "3ac2985e-dcf9-49ff-92fb-943548268de8",
        IaCScanResult(
            id="3ac2985e-dcf9-49ff-92fb-943548268de8",
            type="path_scan",
            iac_engine_version="1.8.0",
            entities_with_incidents=[_generate_file_result_with_vulnerability()],
        ),
    )
    assert collection.has_results


def test_iac_diff_scan_collection_no_new_results() -> None:
    """
    GIVEN an IaC diff scan collection with some results in unchanged/deleted only
    THEN has_results returns False
    """
    collection = IaCDiffScanCollection(
        "3ac2985e-dcf9-49ff-92fb-943548268de8",
        IaCDiffScanResult(
            id="3ac2985e-dcf9-49ff-92fb-943548268de8",
            type="diffscan",
            iac_engine_version="1.8.0",
            entities_with_incidents=IaCDiffScanEntities(
                unchanged=[_generate_file_result_with_vulnerability()],
                deleted=[_generate_file_result_with_vulnerability()],
                new=[],
            ),
        ),
    )
    assert not collection.has_results


def test_iac_diff_scan_collection_new_results() -> None:
    """
    GIVEN an IaC diff scan collection with some results in new
    THEN has_results returns True
    """
    collection = IaCDiffScanCollection(
        "3ac2985e-dcf9-49ff-92fb-943548268de8",
        IaCDiffScanResult(
            id="3ac2985e-dcf9-49ff-92fb-943548268de8",
            type="diffscan",
            iac_engine_version="1.8.0",
            entities_with_incidents=IaCDiffScanEntities(
                unchanged=[],
                deleted=[],
                new=[_generate_file_result_with_vulnerability()],
            ),
        ),
    )
    assert collection.has_results
