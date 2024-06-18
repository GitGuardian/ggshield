from typing import Optional

from pygitguardian.iac_models import IaCDiffScanEntities, IaCDiffScanResult

from ggshield.verticals.iac.collection.filter_ignored import filter_unignored_files
from ggshield.verticals.iac.collection.iac_scan_collection import (
    CollectionType,
    IaCScanCollection,
)


class IaCDiffScanCollection(IaCScanCollection[IaCDiffScanResult]):
    type = CollectionType.DiffScan

    @property
    def has_results(self) -> bool:
        return self.result is not None and bool(self.result.entities_with_incidents.new)

    def get_entities_without_ignored(self) -> Optional[IaCDiffScanEntities]:
        if self.result is None:
            return None

        return IaCDiffScanEntities(
            new=filter_unignored_files(self.result.entities_with_incidents.new),
            unchanged=filter_unignored_files(
                self.result.entities_with_incidents.unchanged
            ),
            deleted=filter_unignored_files(self.result.entities_with_incidents.deleted),
        )

    def get_result_without_ignored(self) -> Optional[IaCDiffScanResult]:
        entities_without_ignored = self.get_entities_without_ignored()
        if self.result is None or entities_without_ignored is None:
            return None

        result_dict = self.result.to_dict()
        del result_dict["entities_with_incidents"]
        return IaCDiffScanResult(
            **result_dict, entities_with_incidents=entities_without_ignored
        )
