from typing import Optional

from pygitguardian.iac_models import IaCScanResult

from ggshield.iac.collection.iac_scan_collection import (
    CollectionType,
    IaCScanCollection,
)


class IaCPathScanCollection(IaCScanCollection):
    def __init__(
        self,
        id: str,
        result: Optional[IaCScanResult],
    ):
        super().__init__(id, result)
        self.type = CollectionType.PathScan

    @property
    def has_results(self) -> bool:
        return self.result is not None and bool(self.result.entities_with_incidents)
