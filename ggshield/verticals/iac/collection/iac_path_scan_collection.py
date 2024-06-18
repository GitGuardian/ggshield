from typing import List, Optional

from pygitguardian.iac_models import IaCFileResult, IaCScanResult

from ggshield.verticals.iac.collection.filter_ignored import filter_unignored_files
from ggshield.verticals.iac.collection.iac_scan_collection import (
    CollectionType,
    IaCScanCollection,
)


class IaCPathScanCollection(IaCScanCollection[IaCScanResult]):
    type = CollectionType.PathScan

    @property
    def has_results(self) -> bool:
        return self.result is not None and bool(self.result.entities_with_incidents)

    def get_entities_without_ignored(self) -> Optional[List[IaCFileResult]]:
        if self.result is None:
            return None

        return filter_unignored_files(self.result.entities_with_incidents)

    def get_result_without_ignored(self) -> Optional[IaCScanResult]:
        entities_without_ignored = self.get_entities_without_ignored()
        if self.result is None or entities_without_ignored is None:
            return None

        result_dict = self.result.to_dict()
        del result_dict["entities_with_incidents"]
        return IaCScanResult(
            **result_dict, entities_with_incidents=entities_without_ignored
        )
