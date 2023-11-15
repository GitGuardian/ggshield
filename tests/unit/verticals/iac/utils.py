from typing import List, Optional

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


def generate_file_result_with_vulnerability(
    filename: str = "file.py",
    policy_id: Optional[str] = "GG_IAC_0024",
    status: Optional[str] = None,
) -> IaCFileResult:
    return IaCFileResult(
        filename,
        [
            IaCVulnerability(
                policy="Leaving public access open exposes your service to the internet",
                policy_id=policy_id,
                line_end=35,
                line_start=1,
                description="The API server of an AKS cluster [...]",
                documentation_url="https://docs.gitguardian.com/iac-security/policies/GG_IAC_0024",
                component="azurerm_kubernetes_cluster.k8s_cluster",
                severity="HIGH",
                status=status,
            )
        ],
    )


def generate_path_scan_collection(file_results: List[IaCFileResult]):
    return IaCPathScanCollection(
        "3ac2985e-dcf9-49ff-92fb-943548268de8",
        IaCScanResult(
            id="3ac2985e-dcf9-49ff-92fb-943548268de8",
            type="path_scan",
            iac_engine_version="1.8.0",
            entities_with_incidents=file_results,
        ),
    )


def generate_diff_scan_collection(
    new: List[IaCFileResult],
    unchanged: List[IaCFileResult] = [],
    deleted: List[IaCFileResult] = [],
):
    return IaCDiffScanCollection(
        "3ac2985e-dcf9-49ff-92fb-943548268de8",
        IaCDiffScanResult(
            id="3ac2985e-dcf9-49ff-92fb-943548268de8",
            type="diff_scan",
            iac_engine_version="1.8.0",
            entities_with_incidents=IaCDiffScanEntities(
                unchanged=unchanged,
                deleted=deleted,
                new=new,
            ),
        ),
    )
