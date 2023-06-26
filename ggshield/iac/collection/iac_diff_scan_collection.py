from typing import Optional

from ggshield.iac.collection.iac_scan_collection import (
    CollectionType,
    IaCScanCollection,
)
from ggshield.iac.iac_scan_models import IaCDiffScanEntities, IaCDiffScanResult


class IaCDiffScanCollection(IaCScanCollection):
    def __init__(
        self,
        id: str,
        result: Optional[IaCDiffScanResult],
    ):
        super().__init__(id, result)
        self.type = CollectionType.DiffScan

    @property
    def has_results(self) -> bool:
        if self.result is None:
            return False
        if isinstance(self.result.entities_with_incidents, IaCDiffScanEntities):
            return (
                bool(self.result.entities_with_incidents.unchanged)
                or bool(self.result.entities_with_incidents.new)
                or bool(self.result.entities_with_incidents.deleted)
            )
        else:
            return bool(self.result.entities_with_incidents)
