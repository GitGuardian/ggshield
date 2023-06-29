from typing import Optional

from ggshield.iac.collection.iac_scan_collection import (
    CollectionType,
    IaCScanCollection,
)
from ggshield.iac.iac_scan_models import IaCDiffScanResult


class IaCDiffScanCollection(IaCScanCollection):
    result: Optional[IaCDiffScanResult]

    def __init__(
        self,
        id: str,
        result: Optional[IaCDiffScanResult],
    ):
        super().__init__(id, result)
        self.type = CollectionType.DiffScan

    @property
    def has_results(self) -> bool:
        return self.result is not None and bool(self.result.entities_with_incidents.new)
