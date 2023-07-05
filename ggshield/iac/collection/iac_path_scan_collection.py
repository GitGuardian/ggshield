from typing import Optional

from pygitguardian.iac_models import IaCScanResult

from ggshield.iac.collection.iac_scan_collection import (
    CollectionType,
    IaCScanCollection,
)


class IaCPathScanCollection(IaCScanCollection):
    type = CollectionType.PathScan
    result: Optional[IaCScanResult]

    @property
    def has_results(self) -> bool:
        return self.result is not None and bool(self.result.entities_with_incidents)
